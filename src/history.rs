use crate::builder::ZincWallet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Minimal inscription metadata attached to a transaction entry.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct InscriptionDetails {
    /// Unique inscription identifier.
    pub id: String,
    /// Global inscription number.
    pub number: i64,
    /// Optional MIME content type.
    pub content_type: Option<String>,
}

/// Normalized wallet transaction item used by API/wasm callers.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TxItem {
    /// Transaction id.
    pub txid: String,
    /// Net amount in sats (positive receive, negative send).
    pub amount_sats: i64,
    /// Computed transaction fee in sats.
    pub fee_sats: u64,
    /// Confirmation timestamp (unix seconds) when confirmed.
    pub confirmation_time: Option<u64>,
    /// Transaction direction label (`send` or `receive`).
    pub tx_type: String, // "send" or "receive"
    #[serde(default)]
    /// Inscriptions observed in transaction outputs.
    pub inscriptions: Vec<InscriptionDetails>,
    #[serde(default)]
    /// Parent transaction ids spent by this transaction.
    pub parent_txids: Vec<String>,
    /// Source-local index used for stable tie-breaking.
    pub index: usize,
}

impl ZincWallet {
    /// Return up to `limit` merged transactions across vault/payment wallets.
    pub fn get_transactions(&self, limit: usize) -> Vec<TxItem> {
        let mut items = Vec::new();

        // 1. Collect from Vault
        self.collect_txs_from_wallet(&self.vault_wallet, &mut items);

        // 2. Collect from Payment (if exists)
        if let Some(payment_wallet) = &self.payment_wallet {
            self.collect_txs_from_wallet(payment_wallet, &mut items);
        }

        // 3. Deduplicate
        let mut combined: std::collections::HashMap<String, TxItem> =
            std::collections::HashMap::new();
        for item in items {
            combined
                .entry(item.txid.clone())
                .and_modify(|existing| {
                    existing.amount_sats += item.amount_sats;
                    if item.confirmation_time > existing.confirmation_time {
                        existing.confirmation_time = item.confirmation_time;
                    }
                    if item.index > existing.index {
                        existing.index = item.index;
                    }
                    // Merge inscription info
                    // We combine lists and deduplicate by ID
                    for new_ins in &item.inscriptions {
                        if !existing.inscriptions.iter().any(|e| e.id == new_ins.id) {
                            existing.inscriptions.push(new_ins.clone());
                        }
                    }
                    // Merge parent txids and keep deterministic order
                    let mut merged_parent_txids: BTreeSet<String> =
                        existing.parent_txids.iter().cloned().collect();
                    merged_parent_txids.extend(item.parent_txids.iter().cloned());
                    existing.parent_txids = merged_parent_txids.into_iter().collect();
                })
                .or_insert(item);
        }

        let mut final_items: Vec<TxItem> = combined.into_values().collect();

        // 4. Sort: Unconfirmed at the top, then newest confirmed first
        final_items.sort_by(|a, b| {
            let a_pending = a.confirmation_time.is_none();
            let b_pending = b.confirmation_time.is_none();

            if a_pending != b_pending {
                return if a_pending {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }

            match (a.confirmation_time, b.confirmation_time) {
                (Some(ta), Some(tb)) if ta != tb => tb.cmp(&ta), // Time descending
                _ => {
                    // Deterministic tie-breakers
                    let idx_order = b.index.cmp(&a.index);
                    if idx_order == std::cmp::Ordering::Equal {
                        b.txid.cmp(&a.txid)
                    } else {
                        idx_order
                    }
                }
            }
        });

        // 5. Limit
        final_items.into_iter().take(limit).collect()
    }

    fn collect_txs_from_wallet(&self, wallet: &bdk_wallet::Wallet, items: &mut Vec<TxItem>) {
        for (i, tx) in wallet.transactions().enumerate() {
            let (sent, received) = wallet.sent_and_received(&tx.tx_node.tx);
            #[allow(clippy::cast_possible_wrap)]
            let amount_sats = received.to_sat() as i64 - sent.to_sat() as i64;

            let fee_sats = wallet
                .calculate_fee(&tx.tx_node.tx)
                .map(bitcoin::Amount::to_sat)
                .unwrap_or(0);

            let confirmation_time = match tx.chain_position {
                bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
                    Some(anchor.confirmation_time)
                }
                bdk_chain::ChainPosition::Unconfirmed { .. } => None,
            };

            let inscriptions = self.get_inscription_details(&tx.tx_node.tx, tx.tx_node.txid);
            let parent_txids = tx
                .tx_node
                .tx
                .input
                .iter()
                .map(|input| input.previous_output.txid.to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            items.push(TxItem {
                txid: tx.tx_node.txid.to_string(),
                amount_sats,
                fee_sats,
                confirmation_time,
                tx_type: if amount_sats >= 0 {
                    "receive".to_string()
                } else {
                    "send".to_string()
                },
                inscriptions,
                parent_txids,
                index: i,
            });
        }
    }

    fn get_inscription_details(
        &self,
        tx: &bitcoin::Transaction,
        txid: bitcoin::Txid,
    ) -> Vec<InscriptionDetails> {
        let mut results = Vec::new();
        for (i, _) in tx.output.iter().enumerate() {
            let vout = match u32::try_from(i) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let outpoint = bitcoin::OutPoint::new(txid, vout);

            let mut inscription = None;
            if !self.ordinals_verified || self.inscribed_utxos.contains(&outpoint) {
                inscription = self.inscriptions.iter().find(|i| i.satpoint.outpoint == outpoint);
            }

            // Find the inscription that matches this outpoint in our cache
            if let Some(ins) = inscription {
                results.push(InscriptionDetails {
                    id: ins.id.clone(),
                    number: ins.number,
                    content_type: ins.content_type.clone(),
                });
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::{Seed64, WalletBuilder};
    use bitcoin::Network;

    #[test]
    fn test_get_transactions_empty() {
        let seed = [0u8; 64];
        let wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .build()
            .unwrap();
        let txs = wallet.get_transactions(50);
        assert_eq!(txs.len(), 0);
    }
}
