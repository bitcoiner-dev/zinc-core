use crate::builder::ZincWallet;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;

/// Maximum number of history rows materialized by one request.
pub const MAX_TRANSACTION_PAGE_SIZE: usize = 100;

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
    /// Source-local index retained for backwards compatibility.
    pub index: usize,
}

/// One bounded page of wallet transaction history.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionPage {
    /// Transactions in pending-first, newest-first order.
    pub items: Vec<TxItem>,
    /// Opaque cursor to pass to the next request.
    pub next_cursor: Option<String>,
    /// Whether at least one older transaction remains.
    pub has_more: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct TransactionCursorV1 {
    version: u8,
    confirmation_time: Option<u64>,
    txid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TxCandidate {
    txid: String,
    confirmation_time: Option<u64>,
}

impl TxCandidate {
    fn cursor(&self) -> TransactionCursorV1 {
        TransactionCursorV1 {
            version: 1,
            confirmation_time: self.confirmation_time,
            txid: self.txid.clone(),
        }
    }
}

fn compare_history_keys(
    a_confirmation_time: Option<u64>,
    a_txid: &str,
    b_confirmation_time: Option<u64>,
    b_txid: &str,
) -> Ordering {
    let a_pending = a_confirmation_time.is_none();
    let b_pending = b_confirmation_time.is_none();

    if a_pending != b_pending {
        return if a_pending {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }

    match (a_confirmation_time, b_confirmation_time) {
        (Some(a_time), Some(b_time)) if a_time != b_time => b_time.cmp(&a_time),
        _ => b_txid.cmp(a_txid),
    }
}

fn compare_candidates(a: &TxCandidate, b: &TxCandidate) -> Ordering {
    compare_history_keys(a.confirmation_time, &a.txid, b.confirmation_time, &b.txid)
}

fn encode_cursor(cursor: &TransactionCursorV1) -> Result<String, String> {
    serde_json::to_vec(cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| format!("Failed to encode transaction cursor: {error}"))
}

fn decode_cursor(cursor: &str) -> Result<TransactionCursorV1, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| "Invalid transaction cursor".to_string())?;
    let decoded: TransactionCursorV1 =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid transaction cursor".to_string())?;
    if decoded.version != 1 || Txid::from_str(&decoded.txid).is_err() {
        return Err("Invalid transaction cursor".to_string());
    }
    Ok(decoded)
}

fn confirmation_time(tx: &bdk_wallet::WalletTx<'_>) -> Option<u64> {
    match tx.chain_position {
        bdk_chain::ChainPosition::Confirmed { anchor, .. } => Some(anchor.confirmation_time),
        bdk_chain::ChainPosition::Unconfirmed { .. } => None,
    }
}

impl ZincWallet {
    /// Return up to `limit` merged transactions across vault/payment wallets.
    ///
    /// This compatibility helper delegates to the first bounded history page.
    pub fn get_transactions(&self, limit: usize) -> Vec<TxItem> {
        self.get_transaction_page(limit, None)
            .map_or_else(|_| Vec::new(), |page| page.items)
    }

    /// Return a bounded transaction-history page.
    ///
    /// The wallet still inspects lightweight BDK transaction keys to find the
    /// next page, but expensive fee, parent, and inscription materialization is
    /// limited to at most `limit + 1` candidates. The opaque cursor is stable
    /// across callers because ordering uses confirmation time and txid only.
    pub fn get_transaction_page(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<TransactionPage, String> {
        let limit = limit.min(MAX_TRANSACTION_PAGE_SIZE);
        if limit == 0 {
            return Ok(TransactionPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }

        let decoded_cursor = cursor.map(decode_cursor).transpose()?;
        let candidate_limit = limit.saturating_add(1);
        let mut candidates = Self::select_wallet_candidates(
            &self.vault_wallet,
            decoded_cursor.as_ref(),
            candidate_limit,
        );
        if let Some(payment_wallet) = &self.payment_wallet {
            candidates.extend(Self::select_wallet_candidates(
                payment_wallet,
                decoded_cursor.as_ref(),
                candidate_limit,
            ));
        }

        let mut candidate_by_txid: HashMap<String, TxCandidate> = HashMap::new();
        for candidate in candidates {
            candidate_by_txid
                .entry(candidate.txid.clone())
                .and_modify(|existing| {
                    if candidate.confirmation_time > existing.confirmation_time {
                        existing.confirmation_time = candidate.confirmation_time;
                    }
                })
                .or_insert(candidate);
        }
        let mut candidates: Vec<TxCandidate> = candidate_by_txid.into_values().collect();
        candidates.sort_by(compare_candidates);
        candidates.truncate(candidate_limit);

        let has_more = candidates.len() > limit;
        let selected_candidates = &candidates[..candidates.len().min(limit)];
        let selected_txids: HashSet<String> = selected_candidates
            .iter()
            .map(|candidate| candidate.txid.clone())
            .collect();
        let inscription_index = self.build_inscription_index();
        let mut combined: HashMap<String, TxItem> = HashMap::with_capacity(selected_txids.len());
        Self::collect_selected_txs_from_wallet(
            &self.vault_wallet,
            &selected_txids,
            &inscription_index,
            &mut combined,
        );
        if let Some(payment_wallet) = &self.payment_wallet {
            Self::collect_selected_txs_from_wallet(
                payment_wallet,
                &selected_txids,
                &inscription_index,
                &mut combined,
            );
        }

        let mut items: Vec<TxItem> = combined.into_values().collect();
        items.sort_by(|a, b| {
            compare_history_keys(a.confirmation_time, &a.txid, b.confirmation_time, &b.txid)
        });

        let next_cursor = if has_more {
            selected_candidates
                .last()
                .map(TxCandidate::cursor)
                .map(|cursor| encode_cursor(&cursor))
                .transpose()?
        } else {
            None
        };

        Ok(TransactionPage {
            items,
            next_cursor,
            has_more,
        })
    }

    fn select_wallet_candidates(
        wallet: &bdk_wallet::Wallet,
        cursor: Option<&TransactionCursorV1>,
        candidate_limit: usize,
    ) -> Vec<TxCandidate> {
        let mut selected = Vec::with_capacity(candidate_limit);
        for tx in wallet.transactions() {
            let candidate = TxCandidate {
                txid: tx.tx_node.txid.to_string(),
                confirmation_time: confirmation_time(&tx),
            };
            if cursor.is_some_and(|cursor| {
                compare_history_keys(
                    candidate.confirmation_time,
                    &candidate.txid,
                    cursor.confirmation_time,
                    &cursor.txid,
                ) != Ordering::Greater
            }) {
                continue;
            }

            let insertion_index = selected
                .binary_search_by(|existing| compare_candidates(existing, &candidate))
                .unwrap_or_else(|index| index);
            if insertion_index < candidate_limit {
                selected.insert(insertion_index, candidate);
                if selected.len() > candidate_limit {
                    selected.pop();
                }
            }
        }
        selected
    }

    fn build_inscription_index(&self) -> HashMap<OutPoint, Vec<InscriptionDetails>> {
        let mut index: HashMap<OutPoint, Vec<InscriptionDetails>> = HashMap::new();
        for inscription in &self.inscriptions {
            index
                .entry(inscription.satpoint.outpoint)
                .or_default()
                .push(InscriptionDetails {
                    id: inscription.id.clone(),
                    number: inscription.number,
                    content_type: inscription.content_type.clone(),
                });
        }
        index
    }

    fn collect_selected_txs_from_wallet(
        wallet: &bdk_wallet::Wallet,
        selected_txids: &HashSet<String>,
        inscription_index: &HashMap<OutPoint, Vec<InscriptionDetails>>,
        combined: &mut HashMap<String, TxItem>,
    ) {
        for (index, tx) in wallet.transactions().enumerate() {
            let txid = tx.tx_node.txid.to_string();
            if !selected_txids.contains(&txid) {
                continue;
            }

            let (sent, received) = wallet.sent_and_received(&tx.tx_node.tx);
            #[allow(clippy::cast_possible_wrap)]
            let amount_sats = received.to_sat() as i64 - sent.to_sat() as i64;
            let fee_sats = wallet
                .calculate_fee(&tx.tx_node.tx)
                .map_or(0, bitcoin::Amount::to_sat);
            let tx_confirmation_time = confirmation_time(&tx);
            let inscriptions = tx
                .tx_node
                .tx
                .output
                .iter()
                .enumerate()
                .filter_map(|(vout, _)| u32::try_from(vout).ok())
                .flat_map(|vout| {
                    inscription_index
                        .get(&OutPoint::new(tx.tx_node.txid, vout))
                        .into_iter()
                        .flatten()
                        .cloned()
                })
                .collect::<Vec<_>>();
            let parent_txids = tx
                .tx_node
                .tx
                .input
                .iter()
                .map(|input| input.previous_output.txid.to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let item = TxItem {
                txid: txid.clone(),
                amount_sats,
                fee_sats,
                confirmation_time: tx_confirmation_time,
                tx_type: if amount_sats >= 0 {
                    "receive".to_string()
                } else {
                    "send".to_string()
                },
                inscriptions,
                parent_txids,
                index,
            };

            combined
                .entry(txid)
                .and_modify(|existing| {
                    existing.amount_sats += item.amount_sats;
                    existing.tx_type = if existing.amount_sats >= 0 {
                        "receive".to_string()
                    } else {
                        "send".to_string()
                    };
                    if item.confirmation_time > existing.confirmation_time {
                        existing.confirmation_time = item.confirmation_time;
                    }
                    if item.index > existing.index {
                        existing.index = item.index;
                    }
                    for inscription in &item.inscriptions {
                        if !existing
                            .inscriptions
                            .iter()
                            .any(|candidate| candidate.id == inscription.id)
                        {
                            existing.inscriptions.push(inscription.clone());
                        }
                    }
                    let mut parent_txids: BTreeSet<String> =
                        existing.parent_txids.iter().cloned().collect();
                    parent_txids.extend(item.parent_txids.iter().cloned());
                    existing.parent_txids = parent_txids.into_iter().collect();
                })
                .or_insert(item);
        }
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
