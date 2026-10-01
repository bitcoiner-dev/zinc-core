//! Current-output synchronization. Address discovery asks for activity counts,
//! never transaction history; transaction reads are limited to current funding
//! outpoints. History is a separate, paginated read path.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "tests/current_state.rs"]
mod tests;

use crate::builder::ZincWallet;
use crate::builder::{SyncRequestType, SyncSleeper};
use bdk_chain::spk_client::SyncRequest;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::KeychainKind;
use bitcoin::{OutPoint, ScriptBuf, TxOut};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Persisted current-output authority, separate from the additive BDK graph.
/// This is cached data, not permission to sign: a fresh chain/Ord receipt is
/// still required after unlock. Descriptor identity prevents cross-wallet use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentStateSnapshot {
    identity: String,
    outputs: BTreeMap<OutPoint, TxOut>,
    active_scripts: BTreeSet<ScriptBuf>,
}

impl CurrentStateSnapshot {
    pub(crate) fn active_scripts(&self) -> &BTreeSet<ScriptBuf> {
        &self.active_scripts
    }
}

impl ZincWallet {
    pub(crate) fn current_state_identity(&self) -> String {
        let describe = |wallet: &bdk_wallet::Wallet| {
            format!(
                "{}:{}:{}",
                wallet.network(),
                wallet.public_descriptor(KeychainKind::External),
                wallet.public_descriptor(KeychainKind::Internal)
            )
        };
        format!(
            "{}|{}",
            describe(&self.vault_wallet),
            self.payment_wallet
                .as_ref()
                .map(describe)
                .unwrap_or_default()
        )
    }

    pub(crate) fn restore_current_state(&mut self, snapshot: Option<CurrentStateSnapshot>) {
        self.current_state = snapshot.filter(|s| s.identity == self.current_state_identity());
        self.mark_current_scripts_used();
    }

    fn mark_current_scripts_used(&mut self) {
        if let Some(snapshot) = &self.current_state {
            for wallet in
                std::iter::once(&mut self.vault_wallet).chain(self.payment_wallet.iter_mut())
            {
                for script in &snapshot.active_scripts {
                    if let Some((keychain, index)) = wallet.derivation_of_spk(script.clone()) {
                        wallet.mark_used(keychain, index);
                    }
                }
            }
        }
    }

    /// BDK's graph is additive. A funding transaction can contain other owned
    /// outputs spent years ago; only the complete UTXO read can authorize them.
    pub(crate) fn current_unspent<'a>(
        &'a self,
        wallet: &'a bdk_wallet::Wallet,
    ) -> impl Iterator<Item = bdk_wallet::LocalOutput> + 'a {
        wallet.list_unspent().filter(|u| {
            self.current_state
                .as_ref()
                .is_none_or(|s| s.outputs.get(&u.outpoint) == Some(&u.txout))
        })
    }

    pub(crate) fn current_balance(&self, wallet: &bdk_wallet::Wallet) -> bdk_wallet::Balance {
        wallet.tx_graph().balance(
            wallet.local_chain(),
            wallet.latest_checkpoint().block_id(),
            bdk_chain::CanonicalizationParams::default(),
            wallet
                .spk_index()
                .outpoints()
                .iter()
                .cloned()
                .filter(|(_, op)| {
                    self.current_state
                        .as_ref()
                        .is_none_or(|s| s.outputs.contains_key(op))
                }),
            |&(keychain, _), _| keychain == KeychainKind::Internal,
        )
    }

    /// The automatic BDK coin selector must exclude stale graph outputs too.
    pub(crate) fn unavailable_outpoints(&self) -> Vec<OutPoint> {
        let mut result: BTreeSet<_> = self.inscribed_utxos.iter().copied().collect();
        if let Some(snapshot) = &self.current_state {
            for wallet in std::iter::once(&self.vault_wallet).chain(self.payment_wallet.iter()) {
                result.extend(
                    wallet
                        .list_unspent()
                        .filter(|u| snapshot.outputs.get(&u.outpoint) != Some(&u.txout))
                        .map(|u| u.outpoint),
                );
            }
        }
        result.into_iter().collect()
    }

    /// Apply both keychains atomically at the existing generation boundary.
    /// Incomplete fetches never produce this type and cannot clear balances.
    pub fn apply_current_state(
        &mut self,
        vault: CurrentStateUpdate,
        payment: Option<CurrentStateUpdate>,
    ) -> Result<Vec<String>, String> {
        let timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::Apply);
        if self.payment_wallet.is_some() != payment.is_some() {
            return Err("Current-state update must cover both wallet roles".into());
        }
        if let Some(payment) = &payment {
            if vault.update.chain.as_ref().map(|c| c.block_id())
                != payment.update.chain.as_ref().map(|c| c.block_id())
            {
                return Err("Wallet roles were read at different chain tips".into());
            }
        }
        let mut outputs = vault.outputs;
        let mut active_scripts = self
            .current_state
            .as_ref()
            .map(|s| s.active_scripts.clone())
            .unwrap_or_default();
        active_scripts.extend(vault.active_scripts);
        let payment_update = if let Some(payment) = payment {
            for (op, output) in payment.outputs {
                if let Some(previous) = outputs.insert(op, output.clone()) {
                    if previous != output {
                        return Err("Conflicting wallet-role output".into());
                    }
                }
            }
            active_scripts.extend(payment.active_scripts);
            Some(payment.update)
        } else {
            None
        };
        let events = self.apply_sync(vault.update, payment_update)?;
        // A fresh complete UTXO response can contradict an old pending spend
        // retained in BDK (eviction, replacement, or a reorg). Tell BDK about
        // the eviction; never implement our own conflict winner or delete its
        // history. A still-confirmed spender is NOT evicted: validation below
        // rejects that inconsistent provider response instead.
        let observed_at = crate::builder::wasm_now_secs();
        for wallet in std::iter::once(&mut self.vault_wallet).chain(self.payment_wallet.iter_mut())
        {
            let evicted: BTreeSet<_> = outputs
                .keys()
                .flat_map(|op| wallet.tx_graph().outspends(*op))
                .filter(|txid| {
                    wallet.get_tx(**txid).is_some_and(|tx| {
                        matches!(
                            tx.chain_position,
                            bdk_chain::ChainPosition::Unconfirmed { .. }
                        )
                    })
                })
                .map(|txid| {
                    (
                        *txid,
                        observed_at.max(
                            wallet
                                .tx_graph()
                                .get_tx_node(*txid)
                                .and_then(|tx| tx.last_seen)
                                .unwrap_or(0),
                        ),
                    )
                })
                .collect();
            wallet.apply_evicted_txs(evicted);
        }
        let old = self.current_state.replace(CurrentStateSnapshot {
            identity: self.current_state_identity(),
            outputs,
            active_scripts,
        });
        // Every advertised output must actually be owned and canonical in BDK.
        // A server race or malformed response fails closed, never exposing a
        // partly verified spendable balance or keeping old Ord authority alive.
        let canonical: BTreeMap<_, _> = std::iter::once(&self.vault_wallet)
            .chain(self.payment_wallet.iter())
            .flat_map(|w| w.list_unspent())
            .map(|u| (u.outpoint, u.txout))
            .collect();
        let valid = self
            .current_state
            .as_ref()
            .unwrap()
            .outputs
            .iter()
            .all(|(op, output)| canonical.get(op) == Some(output));
        if old != self.current_state || !valid {
            self.chain_state_generation = self.chain_state_generation.wrapping_add(1);
            self.wallet_data_generation = self.wallet_data_generation.wrapping_add(1);
            self.invalidate_asset_state();
        }
        if !valid {
            self.current_state.as_mut().unwrap().outputs.clear();
            self.chain_observed_at_unix = None;
            return Err("Current outputs disagree with canonical wallet state".into());
        }
        self.mark_current_scripts_used();
        timing.finish();
        Ok(events)
    }
}

/// A complete keychain read. Transport adapters must finish the entire request
/// before constructing this; failed/partial reads must not become empty sets.
pub struct CurrentStateUpdate {
    pub(crate) update: bdk_wallet::Update,
    pub(crate) outputs: BTreeMap<OutPoint, TxOut>,
    pub(crate) active_scripts: BTreeSet<ScriptBuf>,
}

impl CurrentStateUpdate {
    /// Adapter boundary for non-HTTP transports. The caller must have completed
    /// every requested script read. Core still checks each claimed output
    /// against its funding transaction and canonical owned state on apply.
    pub fn from_complete_read(
        update: bdk_wallet::Update,
        outputs: BTreeMap<OutPoint, TxOut>,
        active_scripts: BTreeSet<ScriptBuf>,
    ) -> Result<Self, String> {
        for (op, output) in &outputs {
            let tx = update
                .tx_update
                .txs
                .iter()
                .find(|tx| tx.compute_txid() == op.txid)
                .ok_or("Missing current-output funding transaction")?;
            if tx.output.get(op.vout as usize) != Some(output) {
                return Err("Current-output funding transaction mismatch".into());
            }
        }
        Ok(Self {
            update,
            outputs,
            active_scripts,
        })
    }
}

/// Network or malformed-response failure. Hosts retain their existing retry
/// scheduler and must never publish a completeness receipt on failure.
#[derive(Debug, thiserror::Error)]
pub enum CurrentStateError {
    #[error(transparent)]
    Backend(#[from] esplora_client::Error),
    #[error("Invalid current-output response: {0}")]
    Invalid(&'static str),
}

impl CurrentStateError {
    /// Preserve transport/error categories for the host's bounded retry policy.
    pub fn backend_failure(&self) -> crate::BackendFailureV1 {
        match self {
            Self::Backend(error) => {
                crate::BackendFailureV1::from_esplora(error, crate::BackendOperationV1::Sync)
            }
            Self::Invalid(_) => crate::BackendFailureV1::invalid_response(
                crate::BackendDependencyV1::Esplora,
                crate::BackendOperationV1::Sync,
            ),
        }
    }
}

struct ScriptRead {
    script: ScriptBuf,
    active: bool,
    outputs: Vec<esplora_client::Utxo>,
}

async fn read_script(
    client: &esplora_client::AsyncClient<SyncSleeper>,
    script: ScriptBuf,
    known_active: bool,
) -> Result<ScriptRead, CurrentStateError> {
    // Historical hints are positive-only: they never authorize cached outputs.
    // For an unknown script, a fresh all-zero chain AND mempool summary proves
    // absence at this read without a redundant UTXO request. Nonzero summaries
    // are gap evidence only; their counts/sums never populate balances or BDK.
    let active = if known_active {
        true
    } else {
        let stats = client.get_scripthash_stats_fresh(&script).await?;
        let mut active = false;
        for summary in [stats.chain_stats, stats.mempool_stats] {
            let has_outputs = summary.funded_txo_count != 0 || summary.funded_txo_sum != 0
                || summary.spent_txo_count != 0 || summary.spent_txo_sum != 0;
            if summary.tx_count == 0 && has_outputs {
                return Err(CurrentStateError::Invalid("inconsistent script statistics"));
            }
            active |= summary.tx_count != 0;
        }
        active
    };
    let outputs = if active {
        client.get_scripthash_utxos(&script).await?
    } else {
        Vec::new()
    };
    Ok(ScriptRead {
        script,
        active,
        outputs,
    })
}

/// Gap-limit state for one keychain of a full scan. Slots are kept in dispatch
/// (index) order; `None` marks a read still in flight.
struct ScanBranch {
    keychain: KeychainKind,
    last_revealed: Option<u32>,
    slots: Vec<(u32, Option<bool>)>,
    settled: usize,
    settled_gap: usize,
    exhausted: bool,
}

impl ScanBranch {
    fn new(keychain: KeychainKind, last_revealed: Option<u32>) -> Self {
        Self { keychain, last_revealed, slots: Vec::new(), settled: 0, settled_gap: 0, exhausted: false }
    }

    /// Activity and every already-revealed index reset the trailing gap.
    fn resets(&self, index: u32, active: Option<bool>) -> bool {
        active == Some(true) || self.last_revealed.is_some_and(|last| index <= last)
    }

    /// Whether the next address is required, treating pending reads as unused.
    /// Activity can only shorten the trailing gap, so this never over-reads.
    fn may_dispatch(&mut self, stop_gap: usize) -> bool {
        if self.exhausted {
            return false;
        }
        // Fold the completed in-order prefix once; it can never change again.
        while self.settled_gap < stop_gap {
            let Some(&(index, Some(active))) = self.slots.get(self.settled) else { break };
            self.settled_gap = if self.resets(index, Some(active)) { 0 } else { self.settled_gap + 1 };
            self.settled += 1;
        }
        let mut gap = self.settled_gap;
        if gap >= stop_gap {
            return false;
        }
        for &(index, active) in &self.slots[self.settled..] {
            gap = if self.resets(index, active) { 0 } else { gap + 1 };
            if gap >= stop_gap {
                return false;
            }
        }
        true
    }

    fn dispatch(&mut self, index: u32) -> usize {
        self.slots.push((index, None));
        self.slots.len() - 1
    }

    fn complete(&mut self, slot: usize, active: bool) {
        self.slots[slot].1 = Some(active);
    }
}

/// Fetch a current-state update with bounded concurrency and no `/txs` calls.
/// A full scan retains gap-limit discovery, including spent-only addresses and
/// change. An incremental scan covers every already-revealed script.
pub async fn fetch_esplora(
    client: &esplora_client::AsyncClient<SyncSleeper>,
    request: SyncRequestType,
    stop_gap: usize,
    parallel_requests: usize,
) -> Result<CurrentStateUpdate, CurrentStateError> {
    fetch_esplora_with_known_activity(
        client,
        request,
        &BTreeSet::new(),
        stop_gap,
        parallel_requests,
    )
    .await
}

/// Reuse descriptor-bound, previously observed activity as conservative gap
/// evidence. These hints never supply outputs, confirmation state or signing
/// authority. The caller obtains them from `ZincWallet::prepare_requests`.
pub async fn fetch_esplora_with_known_activity(
    client: &esplora_client::AsyncClient<SyncSleeper>,
    request: SyncRequestType,
    known_active_scripts: &BTreeSet<ScriptBuf>,
    stop_gap: usize,
    parallel_requests: usize,
) -> Result<CurrentStateUpdate, CurrentStateError> {
    // Only this exact public service has been qualified. Unknown/custom and
    // other network providers remain legacy unless their trusted host opts in.
    let batches = client.url().trim_end_matches('/') == "https://esplora.zincwallet.app";
    fetch_esplora_with_policy(client, request, known_active_scripts, stop_gap, parallel_requests, batches).await
}

/// Current-state read policy for an explicitly qualified batch provider.
/// The flag changes transport only, never address coverage or signing authority.
pub async fn fetch_esplora_with_policy(
    client: &esplora_client::AsyncClient<SyncSleeper>,
    request: SyncRequestType,
    known_active_scripts: &BTreeSet<ScriptBuf>,
    stop_gap: usize,
    parallel_requests: usize,
    batch_outspends: bool,
) -> Result<CurrentStateUpdate, CurrentStateError> {
    if stop_gap == 0 || parallel_requests == 0 {
        return Err(CurrentStateError::Invalid("zero scan bound"));
    }
    let parallel_requests = parallel_requests.min(8);
    let initial_timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::InitialTip);
    let initial_tip = client.get_tip_hash().await?;
    initial_timing.finish();
    let (chain_tip, start_time) = match &request {
        SyncRequestType::Full(r) => (r.chain_tip(), r.start_time()),
        SyncRequestType::Incremental(r) => (r.chain_tip(), r.start_time()),
    };
    let mut reads = Vec::new();
    let mut monitored_txids = Vec::new();
    let mut last_active_indices = BTreeMap::<KeychainKind, u32>::new();
    let coverage_timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::Coverage);
    match request {
        SyncRequestType::Full(mut request) => {
            // Replenish the role's bounded window as each read completes rather
            // than waiting for a whole batch. An address is dispatched only when
            // it is required even if every read still in flight proves unused,
            // so the scanned set equals an in-order scan that stops after
            // `stop_gap` consecutive unused, unrevealed addresses. Keychains
            // share the bound; earlier keychains fill free slots first.
            let mut branches: Vec<_> = request
                .keychains()
                .into_iter()
                .map(|keychain| ScanBranch::new(keychain, request.last_revealed(&keychain)))
                .collect();
            let mut in_flight = futures_util::stream::FuturesUnordered::new();
            loop {
                for (branch_index, branch) in branches.iter_mut().enumerate() {
                    while in_flight.len() < parallel_requests && branch.may_dispatch(stop_gap) {
                        let Some((index, script)) = request.next_spk(branch.keychain) else {
                            branch.exhausted = true;
                            break;
                        };
                        let slot = branch.dispatch(index);
                        let known_active = known_active_scripts.contains(&script);
                        in_flight.push(async move {
                            read_script(client, script, known_active)
                                .await
                                .map(|read| (branch_index, slot, index, read))
                        });
                    }
                }
                let Some(result) = in_flight.next().await else {
                    break;
                };
                let (branch_index, slot, index, read) = result?;
                let branch = &mut branches[branch_index];
                branch.complete(slot, read.active);
                if read.active {
                    last_active_indices
                        .entry(branch.keychain)
                        .and_modify(|last| *last = (*last).max(index))
                        .or_insert(index);
                }
                reads.push(read);
            }
        }
        SyncRequestType::Incremental(mut request) => {
            monitored_txids.extend(request.iter_txids());
            reads = stream::iter(request.iter_spks_with_expected_txids().map(|item| {
                let known_active = known_active_scripts.contains(&item.spk);
                read_script(client, item.spk, known_active)
            }))
            .buffer_unordered(parallel_requests)
            .try_collect()
            .await?;
        }
    }
    coverage_timing.finish();
    let mut outputs = BTreeMap::new();
    let mut active_scripts = BTreeSet::new();
    for read in reads {
        if read.active {
            active_scripts.insert(read.script.clone());
        }
        let mut script_outpoints = BTreeSet::new();
        for output in read.outputs {
            let outpoint = OutPoint::new(output.txid, output.vout);
            if !script_outpoints.insert(outpoint) {
                return Err(CurrentStateError::Invalid("duplicate outpoint"));
            }
            let txout = TxOut {
                value: output.value,
                script_pubkey: read.script.clone(),
            };
            if let Some(previous) = outputs.insert(outpoint, txout.clone()) {
                if previous != txout {
                    return Err(CurrentStateError::Invalid("conflicting outpoint"));
                }
            }
        }
    }

    // Deliberately do NOT put scripts into this BDK request: doing so invokes
    // its unbounded address-history traversal even for an incremental sync.
    let mut funding = SyncRequest::<()>::builder_at(start_time)
        .outpoints(outputs.keys().copied())
        .txids(monitored_txids);
    if let Some(tip) = chain_tip {
        funding = funding.chain_tip(tip);
    }
    let funding_timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::Funding);
    let snapshot_client;
    // A strict, per-operation snapshot feeds the existing BDK graph/anchor
    // implementation. No mutable evidence survives this call. Large collections
    // use the legacy path before any speculative reads, bounding extra memory.
    let txids = outputs.keys().map(|op| op.txid).collect::<BTreeSet<_>>();
    let funding_client = if batch_outspends && !txids.is_empty() && txids.len() <= 64 {
        let mut txs = HashMap::new();
        let mut bytes = 0usize;
        let results = stream::iter(txids.iter().copied()).map(|id| async move {
            let tx = client.get_tx_info(&id).await?.ok_or(CurrentStateError::Invalid("missing funding transaction"))?;
            if tx.txid != id || tx.to_tx().compute_txid() != id {
                return Err(CurrentStateError::Invalid("funding transaction identity mismatch"));
            }
            Ok::<_, CurrentStateError>((id, tx))
        }).buffer_unordered(parallel_requests);
        futures_util::pin_mut!(results);
        while let Some((id, tx)) = results.try_next().await? {
            bytes = bytes.checked_add(tx.to_tx().total_size()).ok_or(CurrentStateError::Invalid("funding snapshot too large"))?;
            if bytes > 16 * 1024 * 1024 { return Err(CurrentStateError::Invalid("funding snapshot too large")); }
            txs.insert(id, tx);
        }
        for (outpoint, expected) in &outputs {
            let tx = txs.get(&outpoint.txid).ok_or(CurrentStateError::Invalid("missing funding transaction"))?;
            if tx.to_tx().output.get(outpoint.vout as usize) != Some(expected) {
                return Err(CurrentStateError::Invalid("funding output mismatch"));
            }
        }
        let ids = txids.iter().copied().collect::<Vec<_>>();
        let mut statuses = HashMap::new();
        for ids in ids.chunks(8) {
            let batch = client.get_outspends_batch(ids).await?;
            for (id, statuses_for_tx) in ids.iter().zip(batch) {
                let tx = txs.get(id).ok_or(CurrentStateError::Invalid("missing funding transaction"))?;
                if statuses_for_tx.len() != tx.vout.len() {
                    return Err(CurrentStateError::Invalid("incomplete outspend coverage"));
                }
                for (index, status) in statuses_for_tx.into_iter().enumerate() {
                    if status.spent != status.txid.is_some()
                        || status.spent != status.vin.is_some()
                        || status.spent != status.status.is_some() {
                        return Err(CurrentStateError::Invalid("inconsistent outspend status"));
                    }
                    statuses.insert((*id, index as u64), status);
                }
            }
        }
        snapshot_client = client.with_read_snapshot(txs, statuses);
        &snapshot_client
    } else { client };
    let response = funding_client
        .sync(funding.build(), parallel_requests)
        .await
        .map_err(|error| CurrentStateError::Backend(*error))?;
    funding_timing.finish();
    let validation_timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::Validation);
    for (outpoint, expected) in &outputs {
        let tx = response
            .tx_update
            .txs
            .iter()
            .find(|tx| tx.compute_txid() == outpoint.txid)
            .ok_or(CurrentStateError::Invalid("missing funding transaction"))?;
        if tx.output.get(outpoint.vout as usize) != Some(expected) {
            return Err(CurrentStateError::Invalid("funding output mismatch"));
        }
        if response.tx_update.txs.iter().any(|tx| {
            tx.input
                .iter()
                .any(|input| input.previous_output == *outpoint)
        }) {
            return Err(CurrentStateError::Invalid("output spent during read"));
        }
    }
    validation_timing.finish();
    let final_timing = crate::startup_diagnostics::Span::phase(crate::startup_diagnostics::Phase::FinalTip);
    if client.get_tip_hash().await? != initial_tip {
        return Err(CurrentStateError::Invalid("chain changed during read"));
    }
    final_timing.finish();
    let mut update: bdk_wallet::Update = response.into();
    update.last_active_indices = last_active_indices;
    Ok(CurrentStateUpdate {
        update,
        outputs,
        active_scripts,
    })
}
