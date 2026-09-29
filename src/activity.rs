//! Bounded Esplora Activity reads, independent of chain/UTXO synchronization.
//! The opaque cursor refers to an in-memory session, never a UI scroll offset.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "tests/activity.rs"]
mod tests;

use crate::{
    builder::SyncSleeper,
    history::{TransactionPage, TxItem},
    ZincWallet,
};
use bitcoin::{ScriptBuf, Txid};
use futures_util::{stream, StreamExt, TryStreamExt};
use std::collections::{BTreeSet, VecDeque};

#[derive(Clone)]
struct AddressPage {
    script: ScriptBuf,
    buffer: VecDeque<esplora_client::Tx>,
    after: Option<Txid>,
    started: bool,
    exhausted: bool,
}

/// A bounded-read session. Hosts must validate their wallet/network/backend
/// generation after network work before publishing or retaining this session.
#[derive(Clone)]
pub struct ActivityPager {
    request_cursor: String,
    cached_page: Option<TransactionPage>,
    identity: String,
    endpoint: String,
    generation: u64,
    serial: u64,
    offset: usize,
    sources: Vec<AddressPage>,
    seen: BTreeSet<Txid>,
    ready: Option<esplora_client::Tx>,
}

impl ZincWallet {
    /// Attach only verified locally known asset metadata; Activity fetches do
    /// not infer clean/protected outputs or establish signing authority.
    pub fn annotate_activity_page(&self, page: &mut TransactionPage) {
        for tx in &mut page.items {
            tx.inscriptions = self
                .inscriptions
                .iter()
                .filter(|inscription| inscription.satpoint.outpoint.txid.to_string() == tx.txid)
                .map(|inscription| crate::history::InscriptionDetails {
                    id: inscription.id.clone(),
                    number: inscription.number,
                    content_type: inscription.content_type.clone(),
                })
                .collect();
        }
    }
    /// Prepare without holding a wallet lock over network I/O. Repeated first
    /// pages start a fresh session; subsequent pages reuse buffered wire rows.
    pub fn prepare_activity_page(
        &mut self,
        endpoint: &str,
        cursor: Option<&str>,
    ) -> Result<ActivityPager, String> {
        let identity = self.current_state_identity();
        if let Some(cursor) = cursor {
            let pager = self
                .activity_pager
                .as_ref()
                .ok_or("Activity cursor expired; refresh Activity")?;
            if pager.identity != identity
                || pager.endpoint != endpoint
                || pager.generation != self.account_generation()
                || (pager.cursor() != cursor && !self.activity_pages.contains_key(cursor))
            {
                return Err("Activity cursor does not match the current wallet page".into());
            }
            let mut pager = pager.clone();
            pager.request_cursor = cursor.to_owned();
            pager.cached_page = self.activity_pages.get(cursor).cloned();
            return Ok(pager);
        }
        self.activity_serial = self.activity_serial.wrapping_add(1);
        self.activity_pages.clear();
        let scripts: BTreeSet<_> = std::iter::once(&self.vault_wallet)
            .chain(self.payment_wallet.iter())
            .flat_map(|w| {
                w.spk_index()
                    .revealed_spks(..)
                    .map(|(_, script)| script.clone())
            })
            .collect();
        Ok(ActivityPager {
            request_cursor: String::new(),
            cached_page: None,
            identity,
            endpoint: endpoint.to_owned(),
            generation: self.account_generation(),
            serial: self.activity_serial,
            offset: 0,
            sources: scripts
                .into_iter()
                .map(|script| AddressPage {
                    script,
                    buffer: VecDeque::new(),
                    after: None,
                    started: false,
                    exhausted: false,
                })
                .collect(),
            seen: BTreeSet::new(),
            ready: None,
        })
    }

    /// Retain buffers only for the exact context that prepared them. This has
    /// no effect on spend authority, Ord classification, or sync completeness.
    pub fn retain_activity_page(
        &mut self,
        pager: ActivityPager,
        page: &TransactionPage,
    ) -> Result<(), String> {
        if pager.identity != self.current_state_identity()
            || pager.generation != self.account_generation()
            || pager.serial != self.activity_serial
            || self.activity_pager.as_ref().is_some_and(|current| {
                current.serial == pager.serial && current.offset > pager.offset
            })
        {
            return Err("Activity result belongs to a retired wallet read".into());
        }
        if pager.request_cursor.is_empty() {
            self.activity_first_page = Some(page.clone());
            self.wallet_data_generation = self.wallet_data_generation.wrapping_add(1);
        }
        self.activity_pages
            .insert(pager.request_cursor.clone(), page.clone());
        self.activity_pager = Some(pager);
        Ok(())
    }
}

impl ActivityPager {
    fn cursor(&self) -> String {
        format!(
            "activity-v1:{}:{}:{}",
            self.generation, self.serial, self.offset
        )
    }

    async fn fill(
        &mut self,
        client: &esplora_client::AsyncClient<SyncSleeper>,
    ) -> Result<(), String> {
        let empty: Vec<_> = self
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.buffer.is_empty() && !source.exhausted)
            .map(|(index, source)| (index, source.clone()))
            .collect();
        let filled: Vec<_> =
            stream::iter(empty.into_iter().map(|(index, mut source)| async move {
                // The mixed /txs endpoint is not a portable page boundary:
                // mempool-electrs can fill its whole first page with confirmed
                // rows (or with pending rows and no confirmed history). Read
                // each bounded stream explicitly, once for mempool and then
                // one confirmed page at a time.
                let mut txs = if !source.started {
                    client
                        .get_mempool_scripthash_txs(&source.script)
                        .await
                        .map_err(|_| "Activity provider unavailable; try again later".to_string())?
                } else {
                    Vec::new()
                };
                if txs.len() > 50 || txs.iter().any(|tx| tx.status.confirmed) {
                    return Err("Invalid pending Activity page".to_string());
                }
                let chain = client
                    .scripthash_txs_chain(&source.script, source.after)
                    .await
                    .map_err(|_| "Activity provider unavailable; try again later".to_string())?;
                let confirmed = chain.len();
                if confirmed > 25 {
                    return Err("Activity provider exceeded its page bound".into());
                }
                if chain.iter().any(|tx| !tx.status.confirmed) {
                    return Err("Confirmed history page contained pending transactions".to_string());
                }
                // Confirmation can happen between the two reads. Prefer the
                // confirmed copy, while still validating every returned row.
                let confirmed_ids: BTreeSet<_> = chain.iter().map(|tx| tx.txid).collect();
                txs.extend(chain);
                let mut unique = BTreeSet::new();
                for tx in &txs {
                    if tx.status.confirmed
                        && (tx.status.block_height.is_none()
                            || tx.status.block_time.is_none()
                            || tx.status.block_hash.is_none())
                    {
                        return Err("Confirmed Activity response is missing block metadata".into());
                    }
                    if tx.to_tx().compute_txid() != tx.txid
                        || !unique.insert((tx.txid, tx.status.confirmed))
                    {
                        return Err("Invalid transaction in Activity response".to_string());
                    }
                    if !tx.vout.iter().any(|out| out.scriptpubkey == source.script)
                        && !tx.vin.iter().any(|input| {
                            input
                                .prevout
                                .as_ref()
                                .is_some_and(|out| out.scriptpubkey == source.script)
                        })
                    {
                        return Err("Activity response does not match requested script".to_string());
                    }
                }
                txs.retain(|tx| tx.status.confirmed || !confirmed_ids.contains(&tx.txid));
                // Confirmed wire pages contain at most 25 rows. Keep extras
                // (including pending rows) buffered for the next UI page.
                if let Some(last) = txs.iter().rev().find(|tx| tx.status.confirmed) {
                    if source.after == Some(last.txid) {
                        return Err("Activity cursor did not advance".into());
                    }
                    source.after = Some(last.txid);
                }
                source.started = true;
                source.exhausted = confirmed < 25;
                source.buffer = txs.into();
                Ok::<_, String>((index, source))
            }))
            .buffer_unordered(5)
            .try_collect()
            .await?;
        for (index, source) in filled {
            self.sources[index] = source;
        }
        Ok(())
    }

    async fn next(
        &mut self,
        client: &esplora_client::AsyncClient<SyncSleeper>,
    ) -> Result<Option<esplora_client::Tx>, String> {
        if let Some(tx) = self.ready.take() {
            return Ok(Some(tx));
        }
        loop {
            self.fill(client).await?;
            // Provider order within a block is retained. Across streams prefer
            // pending, then highest block, with a stable txid tie-break.
            let best = self
                .sources
                .iter()
                .enumerate()
                .filter_map(|(i, source)| {
                    source.buffer.front().map(|tx| {
                        (
                            i,
                            (
                                !tx.status.confirmed,
                                tx.status.block_height.unwrap_or(0),
                                tx.txid,
                            ),
                        )
                    })
                })
                .max_by_key(|(_, key)| *key)
                .map(|(i, _)| i);
            let Some(index) = best else {
                return Ok(None);
            };
            let tx = self.sources[index].buffer.pop_front().unwrap();
            if self.seen.insert(tx.txid) {
                return Ok(Some(tx));
            }
        }
    }

    /// Read only enough wire pages to return N unique wallet transactions plus
    /// one lookahead row. Never walk to the end of an address's history.
    pub async fn fetch(
        mut self,
        client: &esplora_client::AsyncClient<SyncSleeper>,
        limit: usize,
    ) -> Result<(Self, TransactionPage), String> {
        let limit = limit.min(crate::history::MAX_TRANSACTION_PAGE_SIZE);
        if limit == 0 {
            return Err("Activity page size must be positive".into());
        }
        if let Some(page) = self.cached_page.take() {
            if page.items.len() > limit {
                return Err("Use the original Activity page size for this cursor".into());
            }
            return Ok((self, page));
        }
        let scripts: BTreeSet<_> = self.sources.iter().map(|s| s.script.clone()).collect();
        let mut items = Vec::with_capacity(limit);
        while items.len() < limit {
            let Some(tx) = self.next(client).await? else {
                break;
            };
            let received: i128 = tx
                .vout
                .iter()
                .filter(|out| scripts.contains(&out.scriptpubkey))
                .map(|out| i128::from(out.value))
                .sum();
            let sent: i128 = tx
                .vin
                .iter()
                .filter_map(|input| input.prevout.as_ref())
                .filter(|out| scripts.contains(&out.scriptpubkey))
                .map(|out| i128::from(out.value))
                .sum();
            let net = i64::try_from(received - sent).map_err(|_| "Activity amount overflow")?;
            items.push(TxItem {
                txid: tx.txid.to_string(),
                amount_sats: net,
                fee_sats: tx.fee,
                confirmation_time: tx.status.block_time,
                tx_type: if net < 0 { "send" } else { "receive" }.into(),
                inscriptions: Vec::new(),
                parent_txids: tx.vin.iter().map(|i| i.txid.to_string()).collect(),
                index: self.offset + items.len(),
            });
        }
        self.ready = self.next(client).await?;
        self.offset += items.len();
        let has_more = self.ready.is_some();
        let next_cursor = has_more.then(|| self.cursor());
        Ok((
            self,
            TransactionPage {
                items,
                next_cursor,
                has_more,
            },
        ))
    }
}
