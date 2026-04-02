//! Core wallet construction and stateful operations.
//!
//! This module contains the `WalletBuilder` entrypoint plus the primary
//! `ZincWallet` runtime used by both native Rust and WASM bindings.

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_chain::Merge;
use bdk_esplora::EsploraAsyncExt;

use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::address::NetworkUnchecked;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, Network, Transaction};
// use bitcoin::PsbtSighashType; // Failed
use serde::{Deserialize, Serialize};

use crate::error::ZincError;
use crate::keys::ZincMnemonic;

const LOG_TARGET_BUILDER: &str = "zinc_core::builder";

/// Optional controls for PSBT signing behavior.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SignOptions {
    /// Restrict signing to specific input indices.
    pub sign_inputs: Option<Vec<usize>>,
    /// Override the PSBT sighash type as raw `u8`.
    pub sighash: Option<u8>,
    /// If true, finalize the PSBT after signing (for internal wallet use).
    /// Defaults to false for dApp/marketplace compatibility.
    #[serde(default)]
    pub finalize: bool,
}

/// Strongly-typed 64-byte seed material used by canonical constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seed64([u8; 64]);

impl Seed64 {
    /// Create a seed wrapper from a 64-byte array.
    #[must_use]
    pub const fn from_array(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Seed64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Seed64 {
    type Error = ZincError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; 64] = value.try_into().map_err(|_| {
            ZincError::ConfigError(format!(
                "Invalid seed length: {}. Expected 64 bytes.",
                value.len()
            ))
        })?;
        Ok(Self(array))
    }
}

/// Typed request for PSBT creation in native Rust flows.
#[derive(Debug, Clone)]
pub struct CreatePsbtRequest {
    /// Recipient address (network checked at build time).
    pub recipient: Address<NetworkUnchecked>,
    /// Amount in satoshis.
    pub amount: Amount,
    /// Fee rate in sat/vB.
    pub fee_rate: FeeRate,
}

impl CreatePsbtRequest {
    /// Build a typed request from transport-friendly inputs.
    pub fn from_parts(
        recipient: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<Self, ZincError> {
        let recipient = recipient
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| ZincError::ConfigError(format!("Invalid address: {e}")))?;
        let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_vb)
            .ok_or_else(|| ZincError::ConfigError("Invalid fee rate".to_string()))?;

        Ok(Self {
            recipient,
            amount: Amount::from_sat(amount_sats),
            fee_rate,
        })
    }
}

/// Transport-friendly PSBT creation request used by WASM/RPC boundaries.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePsbtTransportRequest {
    /// Recipient address string.
    pub recipient: String,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Fee rate in sat/vB.
    pub fee_rate_sat_vb: u64,
}

impl TryFrom<CreatePsbtTransportRequest> for CreatePsbtRequest {
    type Error = ZincError;

    fn try_from(value: CreatePsbtTransportRequest) -> Result<Self, Self::Error> {
        Self::from_parts(&value.recipient, value.amount_sats, value.fee_rate_sat_vb)
    }
}

/// Address derivation mode for a wallet account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScheme {
    /// Single-wallet mode (taproot only).
    Unified,
    /// Two-wallet mode (taproot + payment).
    Dual,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Copy, Default)]
pub struct WasmSleeper;

#[cfg(target_arch = "wasm32")]
pub struct WasmSleep(gloo_timers::future::TimeoutFuture);

#[cfg(target_arch = "wasm32")]
impl std::future::Future for WasmSleep {
    type Output = ();
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

#[cfg(target_arch = "wasm32")]
// SAFETY: WASM is single-threaded, so we can safely implement Send
#[allow(unsafe_code)]
unsafe impl Send for WasmSleep {}

#[cfg(target_arch = "wasm32")]
impl esplora_client::Sleeper for WasmSleeper {
    type Sleep = WasmSleep;
    fn sleep(dur: std::time::Duration) -> Self::Sleep {
        WasmSleep(gloo_timers::future::TimeoutFuture::new(
            dur.as_millis() as u32
        ))
    }
}

#[cfg(target_arch = "wasm32")]
pub type SyncSleeper = WasmSleeper;

/// Native async sleeper used by Esplora clients on non-WASM targets.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

#[cfg(not(target_arch = "wasm32"))]
impl esplora_client::Sleeper for TokioSleeper {
    type Sleep = tokio::time::Sleep;
    fn sleep(dur: std::time::Duration) -> Self::Sleep {
        tokio::time::sleep(dur)
    }
}

/// Platform-specific async sleeper used for sync calls.
#[cfg(not(target_arch = "wasm32"))]
pub type SyncSleeper = TokioSleeper;

/// Return the current UNIX epoch seconds for the active target.
pub fn now_unix() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Builder for constructing a `ZincWallet` from seed, network, and options.
pub struct WalletBuilder {
    network: Network,
    seed: Vec<u8>,
    scheme: AddressScheme,
    persistence: Option<ZincPersistence>,
    account_index: u32,
}

/// Stateful wallet runtime that owns account wallets and safety state.
pub struct ZincWallet {
    // We use Option for payment_wallet to support Unified mode (where only taproot exists)
    // In Unified mode, payment calls are routed to taproot.
    /// Taproot wallet (always present).
    pub(crate) vault_wallet: Wallet,
    /// Optional payment wallet used in dual-account scheme.
    pub(crate) payment_wallet: Option<Wallet>,
    /// Current address scheme in use.
    pub(crate) scheme: AddressScheme,
    // Store original loaded changesets to merge with staged changes for full persistence
    /// Loaded taproot changeset baseline used for persistence merges.
    pub(crate) loaded_vault_changeset: bdk_wallet::ChangeSet,
    /// Loaded payment changeset baseline used for persistence merges.
    pub(crate) loaded_payment_changeset: Option<bdk_wallet::ChangeSet>,
    /// Active account index.
    pub(crate) account_index: u32,
    // Ordinal Shield State (In-Memory Only)
    /// Outpoints currently marked as inscribed/protected.
    pub(crate) inscribed_utxos: std::collections::HashSet<bitcoin::OutPoint>,
    /// Cached inscription metadata known to the wallet.
    pub(crate) inscriptions: Vec<crate::ordinals::types::Inscription>,
    /// Whether ordinals protection state is currently verified.
    pub(crate) ordinals_verified: bool,
    /// Whether inscription metadata refresh has completed.
    pub(crate) ordinals_metadata_complete: bool,
    master_xprv: bdk_wallet::bitcoin::bip32::Xpriv,
    /// Guard flag used to prevent overlapping sync operations.
    #[allow(dead_code)]
    pub(crate) is_syncing: bool,
    /// Monotonic generation used to invalidate stale async operations.
    pub(crate) account_generation: u64,
}

/// Describes how chain data should be fetched for a keychain set.
pub enum SyncRequestType {
    /// Full scan request.
    Full(FullScanRequest<KeychainKind>),
    /// Incremental sync request.
    Incremental(SyncRequest<(KeychainKind, u32)>),
}

/// Bundled sync request for taproot and optional payment wallets.
pub struct ZincSyncRequest {
    /// Taproot sync request.
    pub taproot: SyncRequestType,
    /// Optional payment sync request.
    pub payment: Option<SyncRequestType>,
}

/// User-facing balance view that separates total, spendable, and inscribed value.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ZincBalance {
    /// Raw combined wallet balance.
    pub total: bdk_wallet::Balance,
    /// Spendable balance after protection filtering.
    pub spendable: bdk_wallet::Balance,
    /// Display-focused spendable balance (payment wallet in dual mode).
    pub display_spendable: bdk_wallet::Balance,
    /// Estimated value currently marked as inscribed/protected.
    pub inscribed: u64,
}

/// Account summary returned by discovery and account listing APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Account index.
    pub index: u32,
    /// Human-readable account label.
    pub label: String,
    /// Taproot receive address.
    #[serde(alias = "vaultAddress")]
    pub taproot_address: String,
    /// Taproot public key for account receive path.
    #[serde(alias = "vaultPublicKey")]
    pub taproot_public_key: String,
    /// Payment receive address when in dual mode.
    pub payment_address: Option<String>,
    /// Payment public key when in dual mode.
    pub payment_public_key: Option<String>,
}

/// Derived descriptor/public-key material for one account discovery candidate.
#[derive(Debug, Clone)]
pub struct DiscoveryAccountPlan {
    /// Account index.
    pub index: u32,
    /// Taproot external descriptor template.
    pub taproot_descriptor: String,
    /// Taproot internal/change descriptor template.
    pub taproot_change_descriptor: String,
    /// Account taproot public key.
    pub taproot_public_key: String,
    /// Optional payment external descriptor template.
    pub payment_descriptor: Option<String>,
    /// Optional payment internal/change descriptor template.
    pub payment_change_descriptor: Option<String>,
    /// Optional payment public key.
    pub payment_public_key: Option<String>,
}

/// Precomputed account discovery context that avoids exposing raw xprv externally.
#[derive(Debug, Clone)]
pub struct DiscoveryContext {
    /// Network for the descriptors in this context.
    pub network: Network,
    /// Address scheme for descriptors in this context.
    pub scheme: AddressScheme,
    /// Account plans to evaluate.
    pub accounts: Vec<DiscoveryAccountPlan>,
}

impl ZincWallet {
    /// Return the cached inscriptions currently tracked by the wallet.
    #[must_use]
    pub fn inscriptions(&self) -> &[crate::ordinals::types::Inscription] {
        &self.inscriptions
    }

    /// Return the current account generation counter.
    #[must_use]
    pub fn account_generation(&self) -> u64 {
        self.account_generation
    }

    /// Return the currently active account index.
    #[must_use]
    pub fn active_account_index(&self) -> u32 {
        self.account_index
    }

    /// Return whether a sync operation is currently in progress.
    #[must_use]
    pub fn is_syncing(&self) -> bool {
        self.is_syncing
    }

    /// Return whether ordinals protection data is verified.
    #[must_use]
    pub fn ordinals_verified(&self) -> bool {
        self.ordinals_verified
    }

    /// Return whether ordinals metadata refresh completed successfully.
    #[must_use]
    pub fn ordinals_metadata_complete(&self) -> bool {
        self.ordinals_metadata_complete
    }

    /// Return `true` when the wallet uses unified addressing.
    pub fn is_unified(&self) -> bool {
        self.scheme == AddressScheme::Unified
    }

    /// Return `true` when wallet state indicates a full scan is needed.
    pub fn needs_full_scan(&self) -> bool {
        // If we have no transactions and the tip is at genesis (or missing), we likely need a full scan
        self.vault_wallet.local_chain().tip().height() == 0
    }

    /// Reveal and return the next taproot receive address.
    pub fn next_taproot_address(&mut self) -> Result<Address, String> {
        let info = self
            .vault_wallet
            .reveal_next_address(KeychainKind::External);
        Ok(info.address)
    }

    /// Peek a taproot receive address at `index` without advancing state.
    pub fn peek_taproot_address(&self, index: u32) -> Address {
        self.vault_wallet
            .peek_address(KeychainKind::External, index)
            .address
    }

    /// Reveal and return the next payment address in dual mode.
    ///
    /// In unified mode this returns the next taproot address.
    pub fn get_payment_address(&mut self) -> Result<bitcoin::Address, String> {
        if self.scheme == AddressScheme::Dual {
            if let Some(wallet) = &mut self.payment_wallet {
                Ok(wallet.reveal_next_address(KeychainKind::External).address)
            } else {
                Err("Payment wallet not initialized".to_string())
            }
        } else {
            self.next_taproot_address()
        }
    }

    /// Peek a payment receive address at `index`.
    ///
    /// In unified mode this resolves to the taproot branch.
    pub fn peek_payment_address(&self, index: u32) -> Option<Address> {
        if self.scheme == AddressScheme::Dual {
            self.payment_wallet
                .as_ref()
                .map(|w| w.peek_address(KeychainKind::External, index).address)
        } else {
            Some(self.peek_taproot_address(index))
        }
    }

    /// Export a persistence snapshot containing merged loaded+staged changesets.
    pub fn export_changeset(&self) -> Result<ZincPersistence, String> {
        // 1. Vault: Start with loaded changeset, merge staged changes
        let mut vault_changeset = self.loaded_vault_changeset.clone();
        if let Some(staged) = self.vault_wallet.staged() {
            vault_changeset.merge(staged.clone());
        }

        // Ensure network and genesis are set (safety net for fresh wallets/empty state)
        let network = self.vault_wallet.network();
        vault_changeset.network = Some(network);

        // Ensure descriptors are set
        vault_changeset.descriptor = Some(
            self.vault_wallet
                .public_descriptor(KeychainKind::External)
                .clone(),
        );
        vault_changeset.change_descriptor = Some(
            self.vault_wallet
                .public_descriptor(KeychainKind::Internal)
                .clone(),
        );

        let genesis_hash = bitcoin::blockdata::constants::genesis_block(network)
            .header
            .block_hash();
        // Check if genesis is missing directly
        vault_changeset
            .local_chain
            .blocks
            .entry(0)
            .or_insert(Some(genesis_hash));

        // 2. Payment: Start with loaded changeset, merge staged changes
        let mut payment_changeset = self.loaded_payment_changeset.clone();

        if let Some(w) = &self.payment_wallet {
            // Ensure we have a base changeset to work with if we initialized one
            let mut pcs = payment_changeset.take().unwrap_or_default();

            if let Some(staged) = w.staged() {
                pcs.merge(staged.clone());
            }

            let net = w.network();
            pcs.network = Some(net);

            // Ensure descriptors are set for payment wallet
            pcs.descriptor = Some(w.public_descriptor(KeychainKind::External).clone());
            pcs.change_descriptor = Some(w.public_descriptor(KeychainKind::Internal).clone());

            let gen_hash = bitcoin::blockdata::constants::genesis_block(net)
                .header
                .block_hash();
            pcs.local_chain.blocks.entry(0).or_insert(Some(gen_hash));
            // Assign back to option
            payment_changeset = Some(pcs);
        } else {
            // If no payment wallet, ensure we don't persist stale data
            payment_changeset = None;
        }

        Ok(ZincPersistence {
            taproot: Some(vault_changeset),
            payment: payment_changeset,
        })
    }

    /// Check whether the configured Esplora endpoint is reachable.
    pub async fn check_connection(esplora_url: &str) -> bool {
        let client =
            esplora_client::Builder::new(esplora_url).build_async_with_sleeper::<SyncSleeper>();

        match client {
            Ok(c) => c.get_height().await.is_ok(),
            Err(_) => false,
        }
    }

    /// Build sync requests for taproot/payment wallets.
    pub fn prepare_requests(&self) -> ZincSyncRequest {
        let now = now_unix();
        // Strict scan policy: only track main receive addresses (external/0).
        // This intentionally avoids scanning non-main derived branches.
        let vault =
            SyncRequestType::Full(Self::main_only_full_scan_request(&self.vault_wallet, now));

        let payment = self.payment_wallet.as_ref().map(|w| {
            // Same strict policy for payment wallet.
            SyncRequestType::Full(Self::main_only_full_scan_request(w, now))
        });

        ZincSyncRequest {
            taproot: vault,
            payment,
        }
    }

    /// Apply taproot/payment updates and return merged event strings.
    pub fn apply_sync(
        &mut self,
        vault_update: impl Into<bdk_wallet::Update>,
        payment_update: Option<impl Into<bdk_wallet::Update>>,
    ) -> Result<Vec<String>, String> {
        let mut all_events = Vec::new();

        // 1. Apply Vault Update
        let vault_events = self
            .vault_wallet
            .apply_update_events(vault_update)
            .map_err(|e| e.to_string())?;

        for event in vault_events {
            all_events.push(format!("taproot:{:?}", event));
        }

        // 2. Apply Payment Update
        if let (Some(w), Some(u)) = (&mut self.payment_wallet, payment_update) {
            let payment_events = w.apply_update_events(u).map_err(|e| e.to_string())?;
            for event in payment_events {
                all_events.push(format!("payment:{:?}", event));
            }
        }

        Ok(all_events)
    }

    /// Rebuild wallet state from current public descriptors, clearing cached sync state.
    pub fn reset_sync_state(&mut self) -> Result<(), String> {
        zinc_log_info!(
            target: LOG_TARGET_BUILDER,
            "resetting wallet sync state (chain mismatch recovery)"
        );

        // 1. Reset Vault Wallet
        let vault_desc = self
            .vault_wallet
            .public_descriptor(KeychainKind::External)
            .to_string();
        let vault_change_desc = self
            .vault_wallet
            .public_descriptor(KeychainKind::Internal)
            .to_string();
        let network = self.vault_wallet.network();

        self.vault_wallet = Wallet::create(vault_desc, vault_change_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| format!("Failed to reset taproot wallet: {}", e))?;
        self.loaded_vault_changeset = bdk_wallet::ChangeSet::default();

        // 2. Reset Payment Wallet (if exists)
        if let Some(w) = &self.payment_wallet {
            let pay_desc = w.public_descriptor(KeychainKind::External).to_string();
            let pay_change_desc = w.public_descriptor(KeychainKind::Internal).to_string();

            self.payment_wallet = Some(
                Wallet::create(pay_desc, pay_change_desc)
                    .network(network)
                    .create_wallet_no_persist()
                    .map_err(|e| format!("Failed to reset payment wallet: {}", e))?,
            );
            self.loaded_payment_changeset = Some(bdk_wallet::ChangeSet::default());
        }

        // 3. Increment account generation to invalidate any in-flight syncs
        self.account_generation += 1;
        self.ordinals_verified = false;
        self.ordinals_metadata_complete = false;

        Ok(())
    }

    /// Run a full sync against Esplora for taproot and optional payment wallets.
    pub async fn sync(&mut self, esplora_url: &str) -> Result<Vec<String>, String> {
        let client = esplora_client::Builder::new(esplora_url)
            .build_async_with_sleeper::<SyncSleeper>()
            .map_err(|e| format!("{:?}", e))?;

        let now = now_unix();
        let vault_req = Self::main_only_full_scan_request(&self.vault_wallet, now);
        let payment_req = self
            .payment_wallet
            .as_ref()
            .map(|w| Self::main_only_full_scan_request(w, now));

        // 1. Sync Vault
        let vault_update = client
            .full_scan(vault_req, 20, 1)
            .await
            .map_err(|e| e.to_string())?;

        // 2. Sync Payment (if exists)
        let payment_update = if let Some(req) = payment_req {
            Some(
                client
                    .full_scan(req, 20, 1)
                    .await
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };

        self.apply_sync(vault_update, payment_update)
    }

    /// Collect the wallet's main receive addresses for ordinals sync.
    ///
    /// Strict scan policy intentionally limits this to index `0` receive paths:
    /// taproot external/0 and (when dual) payment external/0.
    pub fn collect_active_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let taproot_main = self.peek_taproot_address(0).to_string();
        if seen.insert(taproot_main.clone()) {
            addresses.push(taproot_main);
        }

        if let Some(payment_main) = self
            .peek_payment_address(0)
            .map(|address| address.to_string())
        {
            if seen.insert(payment_main.clone()) {
                addresses.push(payment_main);
            }
        }

        addresses
    }

    /// Update the wallet's internal inscription state.
    /// Call this AFTER fetching inscriptions successfully.
    pub fn apply_verified_ordinals_update(
        &mut self,
        inscriptions: Vec<crate::ordinals::types::Inscription>,
        protected_outpoints: std::collections::HashSet<bitcoin::OutPoint>,
    ) -> usize {
        zinc_log_info!(
            target: LOG_TARGET_BUILDER,
            "applying ordinals update: {} inscriptions received",
            inscriptions.len()
        );
        for inscription in &inscriptions {
            zinc_log_debug!(
                target: LOG_TARGET_BUILDER,
                "inscribed outpoint updated: {}",
                inscription.satpoint.outpoint
            );
        }

        self.inscribed_utxos = protected_outpoints;
        self.inscriptions = inscriptions;
        self.ordinals_verified = true;
        self.ordinals_metadata_complete = true;

        zinc_log_info!(
            target: LOG_TARGET_BUILDER,
            "total inscribed_utxos set size: {}",
            self.inscribed_utxos.len()
        );
        self.inscriptions.len()
    }

    /// Apply cached inscription metadata from an untrusted caller boundary.
    ///
    /// This method updates metadata for UI rendering but intentionally does not
    /// mark the wallet's ordinals protection state as verified.
    pub fn apply_unverified_inscriptions_cache(
        &mut self,
        inscriptions: Vec<crate::ordinals::types::Inscription>,
    ) -> usize {
        zinc_log_info!(
            target: LOG_TARGET_BUILDER,
            "applying unverified inscription cache: {} inscriptions received",
            inscriptions.len()
        );

        self.inscribed_utxos.clear();
        self.inscriptions = inscriptions;
        self.ordinals_verified = false;
        self.ordinals_metadata_complete = true;

        self.inscriptions.len()
    }

    fn verify_ord_indexer_is_current(
        &mut self,
        ord_height: u32,
        wallet_height: u32,
    ) -> Result<(), String> {
        if ord_height < wallet_height.saturating_sub(1) {
            self.ordinals_verified = false;
            return Err(format!(
                "Ord Indexer is lagging! Ord: {}, Wallet: {}. Safety lock engaged.",
                ord_height, wallet_height
            ));
        }
        Ok(())
    }

    /// Refresh only ordinals protection outpoints (no inscription metadata details).
    pub async fn sync_ordinals_protection(&mut self, ord_url: &str) -> Result<usize, String> {
        self.ordinals_verified = false;
        let addresses = self.collect_active_addresses();
        let client = crate::ordinals::OrdClient::new(ord_url.to_string());

        // 0. Fetch Ord Indexer Tip to check for lag
        let ord_height = client
            .get_indexing_height()
            .await
            .map_err(|e| e.to_string())?;

        // Get Wallet Tip (from Vault, which is always present)
        let wallet_height = self.vault_wallet.local_chain().tip().height();

        self.verify_ord_indexer_is_current(ord_height, wallet_height)?;

        let mut protected_outpoints = std::collections::HashSet::new();
        for addr_str in addresses {
            let snapshot = client
                .get_address_asset_snapshot(&addr_str)
                .await
                .map_err(|e| format!("Failed to fetch for {}: {}", addr_str, e))?;

            let protected = client
                .get_protected_outpoints_from_outputs(&snapshot.outputs)
                .await
                .map_err(|e| {
                    format!("Failed to fetch protected outputs for {}: {}", addr_str, e)
                })?;
            protected_outpoints.extend(protected);
        }

        self.inscribed_utxos = protected_outpoints;
        self.ordinals_verified = true;
        Ok(self.inscribed_utxos.len())
    }

    /// Refresh inscription metadata used by UI and PSBT analysis.
    pub async fn sync_ordinals_metadata(&mut self, ord_url: &str) -> Result<usize, String> {
        self.ordinals_metadata_complete = false;
        let addresses = self.collect_active_addresses();
        let client = crate::ordinals::OrdClient::new(ord_url.to_string());

        let ord_height = client
            .get_indexing_height()
            .await
            .map_err(|e| e.to_string())?;
        let wallet_height = self.vault_wallet.local_chain().tip().height();
        self.verify_ord_indexer_is_current(ord_height, wallet_height)?;

        let mut all_inscriptions = Vec::new();
        for addr_str in addresses {
            let snapshot = client
                .get_address_asset_snapshot(&addr_str)
                .await
                .map_err(|e| format!("Failed to fetch for {}: {}", addr_str, e))?;

            for inscription_id in snapshot.inscription_ids {
                let inscription = client
                    .get_inscription_details(&inscription_id)
                    .await
                    .map_err(|e| {
                        format!("Failed to fetch details for {}: {}", inscription_id, e)
                    })?;
                all_inscriptions.push(inscription);
            }
        }

        self.inscriptions = all_inscriptions;
        self.ordinals_metadata_complete = true;
        Ok(self.inscriptions.len())
    }

    /// Sync Ordinals (Inscriptions) to build the Shield logic.
    /// This keeps the legacy behavior by running protection and metadata refresh.
    pub async fn sync_ordinals(&mut self, ord_url: &str) -> Result<usize, String> {
        self.sync_ordinals_protection(ord_url).await?;
        self.sync_ordinals_metadata(ord_url).await
    }

    /// Return raw combined BDK balance across taproot and payment wallets.
    pub fn get_raw_balance(&self) -> bdk_wallet::Balance {
        let vault_bal = self.vault_wallet.balance();
        if let Some(payment_wallet) = &self.payment_wallet {
            let pay_bal = payment_wallet.balance();
            bdk_wallet::Balance {
                immature: vault_bal.immature + pay_bal.immature,
                trusted_pending: vault_bal.trusted_pending + pay_bal.trusted_pending,
                untrusted_pending: vault_bal.untrusted_pending + pay_bal.untrusted_pending,
                confirmed: vault_bal.confirmed + pay_bal.confirmed,
            }
        } else {
            vault_bal
        }
    }

    /// Return an ordinals-aware balance view for display and spend checks.
    pub fn get_balance(&self) -> ZincBalance {
        let raw = self.get_raw_balance();

        // Robust Approach:
        let calc_balance = |wallet: &Wallet| {
            let mut bal = bdk_wallet::Balance::default();
            for utxo in wallet.list_unspent() {
                if self.inscribed_utxos.contains(&utxo.outpoint) {
                    zinc_log_debug!(
                        target: LOG_TARGET_BUILDER,
                        "skipping inscribed UTXO while calculating balance: {:?}",
                        utxo.outpoint
                    );
                    continue;
                }
                match utxo.keychain {
                    KeychainKind::Internal | KeychainKind::External => {
                        // This UTXO is safe. Add to balance.
                        match utxo.chain_position {
                            bdk_chain::ChainPosition::Confirmed { .. } => {
                                bal.confirmed += utxo.txout.value;
                            }
                            bdk_chain::ChainPosition::Unconfirmed { .. } => {
                                bal.trusted_pending += utxo.txout.value;
                            }
                        }
                    }
                }
            }
            bal
        };

        let mut safe_bal = calc_balance(&self.vault_wallet);
        if let Some(w) = &self.payment_wallet {
            let p_bal = calc_balance(w);
            safe_bal.confirmed += p_bal.confirmed;
            safe_bal.trusted_pending += p_bal.trusted_pending;
            safe_bal.untrusted_pending += p_bal.untrusted_pending;
            safe_bal.immature += p_bal.immature;
        }

        let display_spendable = if let Some(payment_wallet) = &self.payment_wallet {
            calc_balance(payment_wallet)
        } else {
            safe_bal.clone()
        };

        ZincBalance {
            total: raw.clone(),
            spendable: safe_bal.clone(),
            display_spendable,
            inscribed: raw
                .confirmed
                .to_sat()
                .saturating_sub(safe_bal.confirmed.to_sat())
                + raw
                    .trusted_pending
                    .to_sat()
                    .saturating_sub(safe_bal.trusted_pending.to_sat()), // Estimate
        }
    }

    /// Create an unsigned PSBT for sending BTC.
    pub fn create_psbt_tx(&mut self, request: &CreatePsbtRequest) -> Result<Psbt, ZincError> {
        if !self.ordinals_verified {
            return Err(ZincError::WalletError(
                "Ordinals verification failed - safety lock engaged. Please retry sync."
                    .to_string(),
            ));
        }

        let wallet = if self.scheme == AddressScheme::Dual {
            self.payment_wallet.as_mut().ok_or_else(|| {
                ZincError::WalletError("Payment wallet not initialized".to_string())
            })?
        } else {
            &mut self.vault_wallet
        };

        let recipient = request
            .recipient
            .clone()
            .require_network(wallet.network())
            .map_err(|e| ZincError::ConfigError(format!("Network mismatch: {e}")))?;

        let change_script = wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey();

        let mut builder = wallet.build_tx();
        if !self.inscribed_utxos.is_empty() {
            builder.unspendable(self.inscribed_utxos.iter().cloned().collect());
        }

        builder
            .add_recipient(recipient.script_pubkey(), request.amount)
            .fee_rate(request.fee_rate)
            .drain_to(change_script);

        builder
            .finish()
            .map_err(|e| ZincError::WalletError(format!("Failed to build tx: {e}")))
    }

    /// Create an unsigned PSBT for sending BTC and encode it as base64.
    pub fn create_psbt_base64(&mut self, request: &CreatePsbtRequest) -> Result<String, ZincError> {
        let psbt = self.create_psbt_tx(request)?;
        Ok(Self::encode_psbt_base64(&psbt))
    }

    /// Create an ord-compatible buyer offer PSBT and envelope.
    pub fn create_offer(
        &mut self,
        request: &crate::offer_create::CreateOfferRequest,
    ) -> Result<crate::offer_create::OfferCreateResultV1, ZincError> {
        crate::offer_create::create_offer(self, request)
    }

    /// Create an unsigned PSBT for sending BTC from transport-friendly inputs.
    ///
    /// This method is a migration wrapper for app-boundary callers. New native
    /// Rust integrations should construct `CreatePsbtRequest` and call
    /// `create_psbt_tx` or `create_psbt_base64`.
    #[doc(hidden)]
    #[deprecated(note = "Use create_psbt_base64 with CreatePsbtRequest")]
    pub fn create_psbt(
        &mut self,
        recipient: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<String, String> {
        let request = CreatePsbtRequest::from_parts(recipient, amount_sats, fee_rate_sat_vb)
            .map_err(|e| e.to_string())?;
        self.create_psbt_base64(&request).map_err(|e| e.to_string())
    }

    fn encode_psbt_base64(psbt: &Psbt) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
    }

    /// Sign a PSBT using the wallet's internal keys.
    /// Returns the signed PSBT as base64.
    #[allow(deprecated)]
    pub fn sign_psbt(
        &mut self,
        psbt_base64: &str,
        options: Option<SignOptions>,
    ) -> Result<String, String> {
        use base64::Engine;

        // Decode PSBT from base64
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_base64)
            .map_err(|e| format!("Invalid base64: {e}"))?;

        let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| format!("Invalid PSBT: {e}"))?;

        // ENRICHMENT STEP: Fill in missing witness_utxo from our own wallet if possible
        // This solves "Plain PSBT" issues where dApps don't include UTXO info
        use std::collections::HashMap;
        let mut known_utxos = HashMap::new();

        let collect_utxos = |w: &Wallet, map: &mut HashMap<bitcoin::OutPoint, bitcoin::TxOut>| {
            for utxo in w.list_unspent() {
                map.insert(utxo.outpoint, utxo.txout);
            }
        };

        collect_utxos(&self.vault_wallet, &mut known_utxos);
        if let Some(w) = &self.payment_wallet {
            collect_utxos(w, &mut known_utxos);
        }

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                let outpoint = psbt.unsigned_tx.input[i].previous_output;
                if let Some(txout) = known_utxos.get(&outpoint) {
                    input.witness_utxo = Some(txout.clone());
                }
            }
        }

        // Prepare BDK SignOptions and Apply Overrides (SIGHASH, etc.)
        // We do this BEFORE audit to ensuring we check the actual state being signed.
        let should_finalize = options.as_ref().map(|o| o.finalize).unwrap_or(false);
        let bdk_options = bdk_wallet::SignOptions {
            // CRITICAL: Enable trust_witness_utxo for batch inscriptions where reveal
            // transactions spend outputs from not-yet-broadcast commit transactions.
            // The wallet can't verify these UTXOs from chain state, but we trust the dApp.
            trust_witness_utxo: true,
            // Finalize if explicitly requested (internal wallet use).
            // Default is false for dApp/marketplace compatibility.
            try_finalize: should_finalize,
            ..Default::default()
        };
        let mut inputs_to_sign: Option<Vec<usize>> = None;

        if let Some(opts) = &options {
            if let Some(sighash_u8) = opts.sighash {
                // Use PsbtSighashType to match psbt.inputs type
                let target_sighash = bitcoin::psbt::PsbtSighashType::from_u32(sighash_u8 as u32);
                for input in psbt.inputs.iter_mut() {
                    input.sighash_type = Some(target_sighash);
                }
            }
            inputs_to_sign = opts.sign_inputs.clone();
        }

        if let Some(indices) = inputs_to_sign.as_ref() {
            let mut seen = std::collections::HashSet::new();
            for index in indices {
                if *index >= psbt.inputs.len() {
                    return Err(format!(
                        "Security Violation: sign_inputs index {} is out of bounds for {} inputs",
                        index,
                        psbt.inputs.len()
                    ));
                }
                if !seen.insert(*index) {
                    return Err(format!(
                        "Security Violation: sign_inputs index {} is duplicated",
                        index
                    ));
                }
                let input = &psbt.inputs[*index];
                if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                    return Err(format!(
                        "Security Violation: Requested input #{} is missing UTXO metadata",
                        index
                    ));
                }
            }
        }

        for (index, input) in psbt.inputs.iter().enumerate() {
            if let Some(sighash) = input.sighash_type {
                let value = sighash.to_u32();
                let base_type = value & 0x1f;
                let anyone_can_pay = (value & 0x80) != 0;
                let is_allowed_base = base_type == 0 || base_type == 1; // DEFAULT or ALL

                if anyone_can_pay || !is_allowed_base {
                    return Err(format!(
                        "Security Violation: Sighash type is not allowed on input #{} (value={})",
                        index, value
                    ));
                }
            }
        }

        // Ordinal Shield Audit: BEFORE signing!
        // We must build the known_inscriptions map to check for BURNS (sophisticated check)
        let mut known_inscriptions: HashMap<(bitcoin::Txid, u32), Vec<(String, u64)>> =
            HashMap::new();
        for ins in &self.inscriptions {
            known_inscriptions
                .entry((ins.satpoint.outpoint.txid, ins.satpoint.outpoint.vout))
                .or_default()
                .push((ins.id.clone(), ins.satpoint.offset));
        }
        // Normalize offsets
        for items in known_inscriptions.values_mut() {
            items.sort_by_key(|(_, offset)| *offset);
        }

        if let Err(e) = crate::ordinals::shield::audit_psbt(
            &psbt,
            &known_inscriptions,
            inputs_to_sign.as_deref(),
            self.vault_wallet.network(),
        ) {
            return Err(format!("Security Violation: {}", e));
        }

        // Keep a copy if we need to revert signatures for specific inputs
        let original_psbt = if inputs_to_sign.is_some() {
            Some(psbt.clone())
        } else {
            None
        };

        // Try signing with both, just in case inputs are mixed
        // This is safe because BDK only signs inputs it controls
        self.vault_wallet
            .sign(&mut psbt, bdk_options.clone())
            .map_err(|e| format!("Vault signing failed: {e}"))?;

        if let Some(payment_wallet) = &self.payment_wallet {
            payment_wallet
                .sign(&mut psbt, bdk_options)
                .map_err(|e| format!("Payment signing failed: {e}"))?;
        }

        // CUSTOM SCRIPT-PATH SIGNING for Inscription Reveal Inputs
        // BDK's standard signer only signs inputs where the key's fingerprint matches the wallet.
        // For inscription reveals, the backend sets tap_key_origins with an empty fingerprint,
        // so BDK skips them. We manually sign these inputs if the key matches our ordinals key.
        self.sign_inscription_script_paths(&mut psbt, should_finalize, inputs_to_sign.as_deref())?;

        // If specific inputs were requested, revert the others
        if let Some(indices) = inputs_to_sign.as_ref() {
            // Safe unwrap because we created it above if inputs_to_sign is Some
            let original = original_psbt
                .as_ref()
                .ok_or_else(|| "Security Violation: missing original PSBT snapshot".to_string())?;
            for (i, input) in psbt.inputs.iter_mut().enumerate() {
                if !indices.contains(&i) {
                    *input = original.inputs[i].clone();
                }
            }
        }

        if let Some(indices) = inputs_to_sign.as_ref() {
            let original = original_psbt
                .as_ref()
                .ok_or_else(|| "Security Violation: missing original PSBT snapshot".to_string())?;
            for index in indices {
                let before = &original.inputs[*index];
                let after = &psbt.inputs[*index];

                let signature_changed = before.tap_key_sig != after.tap_key_sig
                    || before.tap_script_sigs != after.tap_script_sigs
                    || before.partial_sigs != after.partial_sigs
                    || before.final_script_witness != after.final_script_witness;

                if !signature_changed {
                    return Err(format!(
                        "Security Violation: Requested input #{} was not signed by this wallet",
                        index
                    ));
                }
            }
        }

        // POST-SIGNING: Log the signature state for debugging
        // With try_finalize: false, BDK places signatures in:
        // - tap_key_sig for Taproot key-path spends
        // - tap_script_sig for Taproot script-path spends (not used for wallet inputs)
        // - partial_sigs for SegWit P2WPKH spends
        for (_i, input) in psbt.inputs.iter().enumerate() {
            if input.tap_key_sig.is_some() {
            } else if !input.tap_script_sigs.is_empty() {
            } else if !input.partial_sigs.is_empty() {
            } else if input.final_script_witness.is_some() {
                // This shouldn't happen with try_finalize: false, but log it
            } else {
                // Input not signed by this wallet - could be unsigned or signed by another party
            }
        }

        let signed_bytes = psbt.serialize();
        let signed_base64 = base64::engine::general_purpose::STANDARD.encode(&signed_bytes);

        Ok(signed_base64)
    }

    /// Analyzes a PSBT for Ordinal Shield protection.
    /// Returns a JSON string containing the AnalysisResult.
    pub fn analyze_psbt(&self, psbt_base64: &str) -> Result<String, String> {
        // Use explicit path to avoid re-export issues if any
        use crate::ordinals::shield::analyze_psbt;
        use base64::Engine;
        use std::collections::HashMap;

        // Decode PSBT
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_base64)
            .map_err(|e| format!("Invalid base64: {e}"))?;

        let mut psbt = match Psbt::deserialize(&psbt_bytes) {
            Ok(p) => p,
            Err(e) => {
                return Err(format!("Invalid PSBT: {e}"));
            }
        };

        // ENRICHMENT STEP: Fill in missing witness_utxo from our own wallet if possible
        // This solves "Plain PSBT" issues where dApps don't include UTXO info
        let mut known_utxos = HashMap::new();

        let collect_utxos = |w: &Wallet, map: &mut HashMap<bitcoin::OutPoint, bitcoin::TxOut>| {
            for utxo in w.list_unspent() {
                map.insert(utxo.outpoint, utxo.txout);
            }
        };

        collect_utxos(&self.vault_wallet, &mut known_utxos);
        if let Some(w) = &self.payment_wallet {
            collect_utxos(w, &mut known_utxos);
        }

        let mut enriched_count = 0;
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                let outpoint = psbt.unsigned_tx.input[i].previous_output;
                if let Some(txout) = known_utxos.get(&outpoint) {
                    input.witness_utxo = Some(txout.clone());
                    enriched_count += 1;
                }
            }
        }

        if enriched_count > 0 {}

        // Build Known Inscriptions Map from internal state
        // Map: (Txid, Vout) -> Vec<(InscriptionID, Offset)>
        let mut known_inscriptions: HashMap<(bitcoin::Txid, u32), Vec<(String, u64)>> =
            HashMap::new();

        // We also need a way to map offsets back to Inscription IDs for the result?
        // The `analyze_psbt` function currently generates keys like "Inscription {N}".
        // Wait, I should probably pass the IDs or handle the mapping better.
        // My implementation in `shield.rs` generates keys.
        // Ideally, `analyze_psbt` should take `HashMap<(Txid, u32), Vec<(u64, String)>>` so it knows the IDs!
        // But for now, let's look at `shield.rs`. It iterates and pushes to `active_inscriptions`.
        // The `known_inscriptions` map is just `Vec<u66>`.
        // This is a limitation of my current `shield.rs` implementation.
        // I should update `shield.rs` to take IDs if I want the frontend to know *which* inscription is being burned.
        // BUT, `shield.rs` is already tested and working with the simplified map.
        // PROPOSAL: Since `shield.rs` generates opaque keys, I should stick to that for V1 reliability.
        // Actually, if I pass a map of `(Txid, Vout) -> Vec<u64>`, I lose the ID association.
        // BUT `self.inscriptions` has the ID.

        // Optimization: Let's rely on the assumption that mapping order is consistent.
        // However, `shield.rs` uses `known_inscriptions.get(...)` which returns a Vec of offsets.
        // If I want the frontend to show specific inscription images, I need the IDs.

        // Let's stick to the current implementation for now. The frontend can re-derive or we just warn "An inscription".
        // Actually, for TDD I implemented it simply.
        // Real user needs to know WHICH inscription.

        for ins in &self.inscriptions {
            known_inscriptions
                .entry((ins.satpoint.outpoint.txid, ins.satpoint.outpoint.vout))
                .or_default()
                .push((ins.id.clone(), ins.satpoint.offset));
        }

        // Sort offsets for deterministic behavior
        for items in known_inscriptions.values_mut() {
            items.sort_by_key(|(_, offset)| *offset);
        }

        let result = match analyze_psbt(&psbt, &known_inscriptions, self.vault_wallet.network()) {
            Ok(r) => r,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        serde_json::to_string(&result).map_err(|e| e.to_string())
    }

    /// Broadcast a signed PSBT to the network.
    /// Returns the transaction ID (txid) as a hex string.
    pub async fn broadcast(
        &mut self,
        signed_psbt_base64: &str,
        esplora_url: &str,
    ) -> Result<String, String> {
        use base64::Engine;

        // Decode PSBT from base64
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_psbt_base64)
            .map_err(|e| format!("Invalid base64: {e}"))?;

        let psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| format!("Invalid PSBT: {e}"))?;

        // Extract the finalized transaction
        let tx: Transaction = psbt
            .extract_tx()
            .map_err(|e| format!("Failed to extract tx: {e}"))?;

        // Broadcast via Esplora
        let client = esplora_client::Builder::new(esplora_url)
            .build_async_with_sleeper::<SyncSleeper>()
            .map_err(|e| format!("Failed to create client: {e:?}"))?;

        let broadcast_res: Result<(), _> = client.broadcast(&tx).await;

        broadcast_res.map_err(|e| format!("Broadcast failed: {e}"))?;

        Ok(tx.compute_txid().to_string())
    }

    /// Sign a message with the private key corresponding to the given address.
    /// Supports both Vault (Taproot) and Payment (SegWit) addresses.
    pub fn sign_message(&self, address: &str, message: &str) -> Result<String, String> {
        use base64::Engine;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Message, Secp256k1};

        // 1. Identify which wallet/keychain owns this address
        let index = 0;
        let vault_addr = self
            .vault_wallet
            .peek_address(KeychainKind::External, index)
            .address
            .to_string();

        let (is_vault, is_payment) = if address == vault_addr {
            (true, false)
        } else if let Some(w) = &self.payment_wallet {
            let pay_addr = w
                .peek_address(KeychainKind::External, index)
                .address
                .to_string();
            (false, address == pay_addr)
        } else {
            (false, false)
        };

        if !is_vault && !is_payment {
            return Err("Address not found in wallet".to_string());
        }

        // 2. Derive Key
        let secp = Secp256k1::new();
        let coin_type = if self.vault_wallet.network() == Network::Bitcoin {
            0
        } else {
            1
        };
        let account = self.account_index;

        // Derivation path components
        let (purpose, chain) = if is_vault { (86, 0) } else { (84, 0) };

        let derivation_path = [
            Self::child_hardened(purpose)?,
            Self::child_hardened(coin_type)?,
            Self::child_hardened(account)?,
            Self::child_normal(chain)?,
            Self::child_normal(index)?,
        ];

        let child_xprv = self
            .master_xprv
            .derive_priv(&secp, &derivation_path)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let priv_key = child_xprv.private_key;

        // 3. Sign Message
        let signature_hash = bitcoin::sign_message::signed_msg_hash(message);
        let msg = Message::from_digest(signature_hash.to_byte_array());

        let sig = secp.sign_ecdsa_recoverable(&msg, &priv_key);
        let (rec_id, sig_bytes_compact) = sig.serialize_compact();

        let mut header = 27 + u8::try_from(rec_id.to_i32()).map_err(|e| format!("Invalid recovery ID: {e}"))?;
        header += 4; // Always compressed

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.push(header);
        sig_bytes.extend_from_slice(&sig_bytes_compact);

        Ok(base64::engine::general_purpose::STANDARD.encode(&sig_bytes))
    }
    /// Derive the taproot public key for this account at `index`.
    pub fn get_taproot_public_key(&self, index: u32) -> Result<String, String> {
        self.derive_public_key(86, index)
    }

    /// Derive the payment public key for this account at `index`.
    ///
    /// In unified mode this uses the same key family as taproot.
    pub fn get_payment_public_key(&self, index: u32) -> Result<String, String> {
        // Dual uses 84 (SegWit), Unified uses 86 (same as taproot)
        let purpose = if self.scheme == AddressScheme::Dual {
            84
        } else {
            86
        };
        self.derive_public_key(purpose, index)
    }

    fn derive_public_key(&self, purpose: u32, index: u32) -> Result<String, String> {
        self.derive_public_key_internal(purpose, self.account_index, index)
    }

    /// Sign inscription reveal script-path inputs that BDK's standard signer missed.
    ///
    /// BDK checks tap_key_origins fingerprint to match wallet keys. Since the inscription
    /// backend uses empty fingerprints, BDK skips these inputs. This method manually
    /// signs if the public key in tap_key_origins matches our ordinals key.
    fn sign_inscription_script_paths(
        &self,
        psbt: &mut Psbt,
        should_finalize: bool,
        allowed_inputs: Option<&[usize]>,
    ) -> Result<(), String> {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::TapLeafHash;

        let secp = Secp256k1::new();

        // Derive the ordinals key (m/86'/coin'/account'/0/0)
        let coin_type = if self.vault_wallet.network() == Network::Bitcoin {
            0
        } else {
            1
        };
        let derivation_path = [
            Self::child_hardened(86)?,
            Self::child_hardened(coin_type)?,
            Self::child_hardened(self.account_index)?,
            Self::child_normal(0)?, // External chain
            Self::child_normal(0)?, // First key
        ];

        let ordinals_xprv = self
            .master_xprv
            .derive_priv(&secp, &derivation_path)
            .map_err(|e| format!("Failed to derive ordinals key: {e}"))?;

        let ordinals_keypair = Keypair::from_secret_key(&secp, &ordinals_xprv.private_key);
        let (ordinals_xonly, _) = ordinals_keypair.x_only_public_key();

        // Collect all prevouts for sighash computation
        let prevouts: Vec<bitcoin::TxOut> = psbt
            .inputs
            .iter()
            .map(|inp| {
                inp.witness_utxo.clone().unwrap_or_else(|| {
                    // Fallback - this shouldn't happen if PSBT is properly formed
                    bitcoin::TxOut {
                        value: bitcoin::Amount::ZERO,
                        script_pubkey: bitcoin::ScriptBuf::new(),
                    }
                })
            })
            .collect();

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            if let Some(indices) = allowed_inputs {
                if !indices.contains(&i) {
                    continue;
                }
            }

            // Skip if already signed or no script-path data
            if !input.tap_script_sigs.is_empty()
                || input.tap_key_sig.is_some()
                || input.final_script_witness.is_some()
            {
                continue;
            }

            // Check if has tap_scripts (inscription reveal inputs have these)
            if input.tap_scripts.is_empty() {
                continue;
            }

            // Accept either explicit tap_key_origins ownership or matching tap_internal_key.
            // Some inscription builders omit/reshape tap_key_origins for script-path reveals.
            let has_our_key_origin = input.tap_key_origins.keys().any(|k| *k == ordinals_xonly);
            let has_matching_internal_key = input
                .tap_internal_key
                .map(|key| key == ordinals_xonly)
                .unwrap_or(false);
            if !has_our_key_origin && !has_matching_internal_key {
                continue;
            }

            // Get the script and leaf version from tap_scripts
            let (control_block, (script, leaf_version)) = input
                .tap_scripts
                .iter()
                .next()
                .ok_or_else(|| format!("Input {} has empty tap_scripts", i))?;

            let leaf_hash = TapLeafHash::from_script(script, *leaf_version);

            // Compute the script-path sighash
            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(|e| format!("Failed to compute script sighash for input {}: {e}", i))?;

            // Sign it
            let msg = Message::from_digest_slice(sighash.as_ref())
                .map_err(|e| format!("Invalid sighash message: {e}"))?;
            let signature = secp.sign_schnorr(&msg, &ordinals_keypair);

            // Create the TapScriptSig (signature + sighash type)
            let tap_sig = bitcoin::taproot::Signature {
                signature,
                sighash_type: TapSighashType::Default,
            };

            // Add to tap_script_sigs with (public_key, leaf_hash) as key
            let tap_sig_serialized = tap_sig.serialize();
            input
                .tap_script_sigs
                .insert((ordinals_xonly, leaf_hash), tap_sig);

            if should_finalize {
                let mut witness = bitcoin::Witness::new();
                witness.push(tap_sig_serialized);
                witness.push(script.as_bytes());
                witness.push(control_block.serialize());
                input.final_script_witness = Some(witness);
            }
        }

        Ok(())
    }

    /// Build account summaries for indices `[0, count)`.
    pub fn get_accounts(&self, count: u32) -> Vec<Account> {
        let mut accounts = Vec::new();
        let network = self.vault_wallet.network();
        let coin_type = i32::from(network != Network::Bitcoin);

        for i in 0..count {
            // Derive Vault Address
            let vault_desc = format!("tr({}/86'/{coin_type}'/{i}'/0/*)", self.master_xprv);
            let vault_change_desc = format!("tr({}/86'/{coin_type}'/{i}'/1/*)", self.master_xprv);

            // Temporary wallet for peeking
            if let Ok(vw) = Wallet::create(vault_desc, vault_change_desc)
                .network(network)
                .create_wallet_no_persist()
            {
                let taproot_address = vw
                    .peek_address(KeychainKind::External, 0)
                    .address
                    .to_string();
                let taproot_public_key = self
                    .derive_public_key_internal(86, i, 0)
                    .unwrap_or_default();

                let (payment_address, payment_public_key) = if self.scheme == AddressScheme::Dual {
                    let pay_desc = format!("wpkh({}/84'/{coin_type}'/{i}'/0/*)", self.master_xprv);
                    let pay_change_desc =
                        format!("wpkh({}/84'/{coin_type}'/{i}'/1/*)", self.master_xprv);

                    if let Ok(pw) = Wallet::create(pay_desc, pay_change_desc)
                        .network(network)
                        .create_wallet_no_persist()
                    {
                        (
                            Some(
                                pw.peek_address(KeychainKind::External, 0)
                                    .address
                                    .to_string(),
                            ),
                            Some(
                                self.derive_public_key_internal(84, i, 0)
                                    .unwrap_or_default(),
                            ),
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (
                        Some(taproot_address.clone()),
                        Some(taproot_public_key.clone()),
                    )
                };

                accounts.push(Account {
                    index: i,
                    label: format!("Account {}", i + 1),
                    taproot_address,
                    taproot_public_key,
                    payment_address,
                    payment_public_key,
                });
            }
        }
        accounts
    }

    fn child_hardened(index: u32) -> Result<bdk_wallet::bitcoin::bip32::ChildNumber, String> {
        bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(index)
            .map_err(|e| format!("Invalid hardened child index {index}: {e}"))
    }

    fn child_normal(index: u32) -> Result<bdk_wallet::bitcoin::bip32::ChildNumber, String> {
        bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(index)
            .map_err(|e| format!("Invalid normal child index {index}: {e}"))
    }

    fn account_discovery_plan_from_xprv(
        master_xprv: bdk_wallet::bitcoin::bip32::Xpriv,
        network: Network,
        scheme: AddressScheme,
        account_index: u32,
    ) -> Result<DiscoveryAccountPlan, String> {
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };

        let vault_path = [
            Self::child_hardened(86)?,
            Self::child_hardened(coin_type)?,
            Self::child_hardened(account_index)?,
        ];
        let vault_account_xprv = master_xprv.derive_priv(&secp, &vault_path).map_err(|e| {
            format!("Failed to derive taproot account xprv for account {account_index}: {e}")
        })?;
        let vault_account_xpub =
            bdk_wallet::bitcoin::bip32::Xpub::from_priv(&secp, &vault_account_xprv);
        let taproot_descriptor = format!("tr({}/0/*)", vault_account_xpub);
        let taproot_change_descriptor = format!("tr({}/1/*)", vault_account_xpub);

        let vault_pub_path = [Self::child_normal(0)?, Self::child_normal(0)?];
        let vault_pubkey = vault_account_xpub
            .derive_pub(&secp, &vault_pub_path)
            .map_err(|e| {
                format!("Failed to derive taproot public key for account {account_index}: {e}")
            })?
            .public_key;
        let taproot_public_key = vault_pubkey.x_only_public_key().0.to_string();

        let (payment_descriptor, payment_change_descriptor, payment_public_key) = if scheme
            == AddressScheme::Dual
        {
            let payment_path = [
                Self::child_hardened(84)?,
                Self::child_hardened(coin_type)?,
                Self::child_hardened(account_index)?,
            ];
            let payment_account_xprv =
                master_xprv.derive_priv(&secp, &payment_path).map_err(|e| {
                    format!(
                        "Failed to derive payment account xprv for account {account_index}: {e}"
                    )
                })?;
            let payment_account_xpub =
                bdk_wallet::bitcoin::bip32::Xpub::from_priv(&secp, &payment_account_xprv);
            let payment_pubkey = payment_account_xpub
                .derive_pub(&secp, &vault_pub_path)
                .map_err(|e| {
                    format!("Failed to derive payment public key for account {account_index}: {e}")
                })?
                .public_key
                .to_string();

            (
                Some(format!("wpkh({}/0/*)", payment_account_xpub)),
                Some(format!("wpkh({}/1/*)", payment_account_xpub)),
                Some(payment_pubkey),
            )
        } else {
            (None, None, None)
        };

        Ok(DiscoveryAccountPlan {
            index: account_index,
            taproot_descriptor,
            taproot_change_descriptor,
            taproot_public_key,
            payment_descriptor,
            payment_change_descriptor,
            payment_public_key,
        })
    }

    fn build_discovery_context_from_xprv(
        master_xprv: bdk_wallet::bitcoin::bip32::Xpriv,
        network: Network,
        scheme: AddressScheme,
        start: u32,
        count: u32,
    ) -> Result<DiscoveryContext, String> {
        let mut accounts = Vec::new();
        let end = start.saturating_add(count);

        for account_index in start..end {
            accounts.push(Self::account_discovery_plan_from_xprv(
                master_xprv,
                network,
                scheme,
                account_index,
            )?);
        }

        Ok(DiscoveryContext {
            network,
            scheme,
            accounts,
        })
    }

    /// Build discovery context for accounts in `[start, start + count)`.
    pub fn build_discovery_context(
        &self,
        start: u32,
        count: u32,
    ) -> Result<DiscoveryContext, String> {
        Self::build_discovery_context_from_xprv(
            self.master_xprv,
            self.vault_wallet.network(),
            self.scheme,
            start,
            count,
        )
    }

    /// Discover active accounts from index `0` up to `count`.
    pub async fn discover_active_accounts(
        &self,
        esplora_url: &str,
        count: u32,
        gap: u32,
    ) -> Result<Vec<Account>, String> {
        self.discover_active_accounts_range(esplora_url, 0, count, gap)
            .await
    }

    /// Discover active accounts in `[start, start + count)`.
    pub async fn discover_active_accounts_range(
        &self,
        esplora_url: &str,
        start: u32,
        count: u32,
        gap: u32,
    ) -> Result<Vec<Account>, String> {
        let context = self.build_discovery_context(start, count)?;
        Self::discover_accounts_with_context(context, esplora_url, gap).await
    }

    /// Discover active accounts using a pre-built discovery context.
    pub async fn discover_accounts_with_context(
        context: DiscoveryContext,
        esplora_url: &str,
        _gap: u32,
    ) -> Result<Vec<Account>, String> {
        let client = esplora_client::Builder::new(esplora_url)
            .build_async_with_sleeper::<SyncSleeper>()
            .map_err(|e| format!("{e:?}"))?;

        let mut active_accounts = Vec::new();

        for plan in context.accounts {
            let vault_wallet = Wallet::create(
                plan.taproot_descriptor.clone(),
                plan.taproot_change_descriptor.clone(),
            )
            .network(context.network)
            .create_wallet_no_persist()
            .map_err(|e| e.to_string())?;

            let taproot_main = vault_wallet.peek_address(KeychainKind::External, 0).address;
            let taproot_stats = client
                .get_address_stats(&taproot_main)
                .await
                .map_err(|e| e.to_string())?;
            let mut has_activity =
                taproot_stats.chain_stats.tx_count > 0 || taproot_stats.mempool_stats.tx_count > 0;

            let mut payment_wallet: Option<Wallet> = None;
            if let (Some(pay_desc), Some(pay_change_desc)) = (
                plan.payment_descriptor.as_ref(),
                plan.payment_change_descriptor.as_ref(),
            ) {
                if let Ok(created_wallet) =
                    Wallet::create(pay_desc.clone(), pay_change_desc.clone())
                        .network(context.network)
                        .create_wallet_no_persist()
                {
                    if !has_activity {
                        let payment_main = created_wallet
                            .peek_address(KeychainKind::External, 0)
                            .address;
                        let payment_stats = client
                            .get_address_stats(&payment_main)
                            .await
                            .map_err(|e| e.to_string())?;
                        if payment_stats.chain_stats.tx_count > 0
                            || payment_stats.mempool_stats.tx_count > 0
                        {
                            has_activity = true;
                        }
                    }
                    payment_wallet = Some(created_wallet);
                }
            }

            if has_activity {
                let taproot_address = vault_wallet
                    .peek_address(KeychainKind::External, 0)
                    .address
                    .to_string();
                let taproot_public_key = plan.taproot_public_key.clone();
                let payment_address = if context.scheme == AddressScheme::Dual {
                    payment_wallet.as_ref().map(|wallet| {
                        wallet
                            .peek_address(KeychainKind::External, 0)
                            .address
                            .to_string()
                    })
                } else {
                    Some(taproot_address.clone())
                };
                let payment_public_key = if context.scheme == AddressScheme::Dual {
                    plan.payment_public_key.clone()
                } else {
                    Some(taproot_public_key.clone())
                };

                active_accounts.push(Account {
                    index: plan.index,
                    label: format!("Account {}", plan.index + 1),
                    taproot_address,
                    taproot_public_key,
                    payment_address,
                    payment_public_key,
                });
            }
        }

        Ok(active_accounts)
    }

    fn main_only_full_scan_request(
        wallet: &Wallet,
        start_time: u64,
    ) -> FullScanRequest<KeychainKind> {
        let main_receive_spk = wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey();

        FullScanRequest::builder_at(start_time)
            .chain_tip(wallet.local_chain().tip())
            .spks_for_keychain(
                KeychainKind::External,
                std::iter::once((0u32, main_receive_spk)),
            )
            .build()
    }

    /// Switch the active account and reset account-scoped runtime state.
    pub fn set_active_account(&mut self, index: u32) -> Result<(), String> {
        if self.account_index == index {
            return Ok(());
        }

        let network = self.vault_wallet.network();
        let coin_type = i32::from(network != Network::Bitcoin);

        // Rebuild Vault Wallet
        let vault_desc = format!("tr({}/86'/{coin_type}'/{index}'/0/*)", self.master_xprv);
        let vault_change_desc = format!("tr({}/86'/{coin_type}'/{index}'/1/*)", self.master_xprv);

        let next_vault_wallet = Wallet::create(vault_desc, vault_change_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| e.to_string())?;

        // Rebuild Payment Wallet if in Dual mode
        let next_payment_wallet = if self.scheme == AddressScheme::Dual {
            let pay_desc = format!("wpkh({}/84'/{coin_type}'/{index}'/0/*)", self.master_xprv);
            let pay_change_desc =
                format!("wpkh({}/84'/{coin_type}'/{index}'/1/*)", self.master_xprv);

            Some(
                Wallet::create(pay_desc, pay_change_desc)
                    .network(network)
                    .create_wallet_no_persist()
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };

        self.account_index = index;
        self.vault_wallet = next_vault_wallet;
        self.payment_wallet = next_payment_wallet;
        self.loaded_vault_changeset = bdk_wallet::ChangeSet::default();
        self.loaded_payment_changeset = None;
        self.inscribed_utxos.clear();
        self.inscriptions.clear();
        self.ordinals_verified = false;
        self.ordinals_metadata_complete = false;
        self.is_syncing = false;
        self.account_generation = self.account_generation.wrapping_add(1);

        Ok(())
    }

    /// Switch between unified and dual address schemes.
    pub fn set_address_scheme(&mut self, scheme: AddressScheme) -> Result<(), String> {
        if self.scheme == scheme {
            return Ok(());
        }

        self.scheme = scheme;
        let network = self.vault_wallet.network();
        let index = self.account_index;
        let coin_type = i32::from(network != Network::Bitcoin);

        if scheme == AddressScheme::Dual {
            let pay_desc = format!("wpkh({}/84'/{coin_type}'/{index}'/0/*)", self.master_xprv);
            let pay_change_desc =
                format!("wpkh({}/84'/{coin_type}'/{index}'/1/*)", self.master_xprv);

            self.payment_wallet = Some(
                Wallet::create(pay_desc, pay_change_desc)
                    .network(network)
                    .create_wallet_no_persist()
                    .map_err(|e| e.to_string())?,
            );
        } else {
            self.payment_wallet = None;
        }

        Ok(())
    }

    fn derive_public_key_internal(
        &self,
        purpose: u32,
        account: u32,
        index: u32,
    ) -> Result<String, String> {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();

        let coin_type = if self.vault_wallet.network() == Network::Bitcoin {
            0
        } else {
            1
        };
        let chain = 0;

        let derivation_path = [
            Self::child_hardened(purpose)?,
            Self::child_hardened(coin_type)?,
            Self::child_hardened(account)?,
            Self::child_normal(chain)?,
            Self::child_normal(index)?,
        ];

        let child_xprv = self
            .master_xprv
            .derive_priv(&secp, &derivation_path)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let public_key = child_xprv.private_key.public_key(&secp);

        // Check purpose to decide format
        if purpose == 86 {
            // Taproot (BIP-86) uses 32-byte x-only public keys
            let (x_only, _parity) = public_key.x_only_public_key();
            Ok(x_only.to_string())
        } else {
            // SegWit (BIP-84) uses 33-byte compressed public keys
            Ok(public_key.to_string())
        }
    }
}

/// Serializable persistence snapshot for taproot/payment wallet changesets.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ZincPersistence {
    /// Optional taproot changeset.
    #[serde(default, alias = "vault")]
    pub taproot: Option<bdk_wallet::ChangeSet>,
    /// Optional payment changeset.
    pub payment: Option<bdk_wallet::ChangeSet>,
}

impl WalletBuilder {
    /// Create a new builder from network and a strongly typed 64-byte seed.
    pub fn from_seed(network: Network, seed: Seed64) -> Self {
        Self {
            network,
            seed: seed.as_ref().to_vec(),
            scheme: AddressScheme::Unified,
            persistence: None,
            account_index: 0,
        }
    }

    /// Create a new builder from network and mnemonic material.
    pub fn from_mnemonic(network: Network, mnemonic: &ZincMnemonic) -> Self {
        let seed = mnemonic.to_seed("");
        Self::from_seed(network, Seed64::from_array(*seed))
    }

    /// Create a new builder from `network` and seed bytes.
    #[doc(hidden)]
    #[deprecated(note = "Use from_seed or from_mnemonic")]
    pub fn new(network: Network, seed: &[u8]) -> Self {
        Self {
            network,
            seed: seed.to_vec(),
            scheme: AddressScheme::Unified,
            persistence: None,
            account_index: 0,
        }
    }

    #[must_use]
    /// Set wallet address scheme (`Unified` or `Dual`).
    pub fn with_scheme(mut self, scheme: AddressScheme) -> Self {
        self.scheme = scheme;
        self
    }

    #[must_use]
    /// Set active account index used for descriptor derivation.
    pub fn with_account_index(mut self, account_index: u32) -> Self {
        self.account_index = account_index;
        self
    }

    #[must_use]
    /// Attach typed persistence state to hydrate wallet state.
    pub fn with_persistence_state(mut self, persistence: ZincPersistence) -> Self {
        self.persistence = Some(persistence);
        self
    }

    /// Attach serialized persistence JSON to hydrate wallet state.
    pub fn with_persistence(mut self, json: &str) -> Result<Self, String> {
        let parsed = serde_json::from_str::<ZincPersistence>(json)
            .map_err(|e| format!("Persistence deserialization failed: {e}"))?;
        self.persistence = Some(parsed);
        Ok(self)
    }

    /// Build a fully initialized `ZincWallet`.
    pub fn build(self) -> Result<ZincWallet, String> {
        let xprv = bdk_wallet::bitcoin::bip32::Xpriv::new_master(self.network, &self.seed)
            .map_err(|e| e.to_string())?;

        let coin_type = i32::from(self.network != Network::Bitcoin);
        let account = self.account_index;

        // 1. Vault Wallet (Always BIP-86 Taproot)
        // Manual descriptor construction for dynamic account index support
        // Template: tr(xprv/86'/coin'/account'/0/*)
        let vault_desc_str = format!("tr({}/86'/{coin_type}'/{account}'/0/*)", xprv);
        let vault_change_desc_str = format!("tr({}/86'/{coin_type}'/{account}'/1/*)", xprv);

        let (vault_wallet, loaded_vault_changeset) = if let Some(p) = &self.persistence {
            let (wallet, changeset) = if let Some(changeset) = &p.taproot {
                // Attempt to load with persistence
                let res = Wallet::load()
                    .descriptor(KeychainKind::External, Some(vault_desc_str.clone()))
                    .descriptor(KeychainKind::Internal, Some(vault_change_desc_str.clone()))
                    .extract_keys()
                    .load_wallet_no_persist(changeset.clone());

                match res {
                    Ok(Some(w)) => (w, changeset.clone()),
                    Ok(None) => {
                        let w = Wallet::create(vault_desc_str, vault_change_desc_str)
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| e.to_string())?;
                        (w, bdk_wallet::ChangeSet::default())
                    }
                    Err(_e) => {
                        let w = Wallet::create(vault_desc_str, vault_change_desc_str)
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| e.to_string())?;
                        (w, bdk_wallet::ChangeSet::default())
                    }
                }
            } else {
                let w = Wallet::create(vault_desc_str, vault_change_desc_str)
                    .network(self.network)
                    .create_wallet_no_persist()
                    .map_err(|e| e.to_string())?;
                (w, bdk_wallet::ChangeSet::default())
            };

            (wallet, changeset)
        } else {
            let wallet = Wallet::create(vault_desc_str, vault_change_desc_str)
                .network(self.network)
                .create_wallet_no_persist()
                .map_err(|e| e.to_string())?;
            (wallet, bdk_wallet::ChangeSet::default())
        };

        // 2. Payment Wallet (Only for Dual Scheme: BIP-84 SegWit)
        let (payment_wallet, loaded_payment_changeset) = if self.scheme == AddressScheme::Dual {
            // Manual descriptor construction for dynamic account index support
            // Template: wpkh(xprv/84'/coin'/account'/0/*)
            let payment_desc_str = format!("wpkh({}/84'/{coin_type}'/{account}'/0/*)", xprv);
            let payment_change_desc_str = format!("wpkh({}/84'/{coin_type}'/{account}'/1/*)", xprv);

            let (wallet, changeset) = if let Some(p) = &self.persistence {
                if let Some(changeset) = &p.payment {
                    let res = Wallet::load()
                        .descriptor(KeychainKind::External, Some(payment_desc_str.clone()))
                        .descriptor(
                            KeychainKind::Internal,
                            Some(payment_change_desc_str.clone()),
                        )
                        .extract_keys()
                        .load_wallet_no_persist(changeset.clone());

                    match res {
                        Ok(Some(w)) => (w, Some(changeset.clone())),
                        Ok(None) => {
                            let w = Wallet::create(
                                payment_desc_str.clone(),
                                payment_change_desc_str.clone(),
                            )
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| e.to_string())?;
                            (w, None)
                        }
                        Err(_e) => {
                            let w = Wallet::create(
                                payment_desc_str.clone(),
                                payment_change_desc_str.clone(),
                            )
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| e.to_string())?;
                            (w, None)
                        }
                    }
                } else {
                    let wallet =
                        Wallet::create(payment_desc_str.clone(), payment_change_desc_str.clone())
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| e.to_string())?;
                    (wallet, None)
                }
            } else {
                let wallet = Wallet::create(payment_desc_str, payment_change_desc_str)
                    .network(self.network)
                    .create_wallet_no_persist()
                    .map_err(|e| e.to_string())?;
                (wallet, None)
            };

            (Some(wallet), changeset)
        } else {
            (None, None)
        };

        Ok(ZincWallet {
            vault_wallet,
            payment_wallet,
            scheme: self.scheme,
            loaded_vault_changeset,
            loaded_payment_changeset,
            account_index: self.account_index,
            inscribed_utxos: std::collections::HashSet::default(), // Initialize empty
            inscriptions: Vec::new(),
            ordinals_verified: false,
            ordinals_metadata_complete: false,
            master_xprv: xprv,
            is_syncing: false,
            account_generation: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ZincMnemonic;

    #[test]
    fn test_builder_ignores_mismatched_persistence() {
        // 1. Setup: Generate a mnemonic for consistent testing
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let network = Network::Regtest; // Use Regtest for generating addresses

        // 2. Create "Account 1" persistence
        // We simulate a scenario where the user was previously on Account 1
        let mut builder_acc1 = WalletBuilder::from_seed(network, Seed64::from_array(*seed));
        builder_acc1 = builder_acc1.with_account_index(1);
        let mut wallet_acc1 = builder_acc1.build().unwrap();

        let acc1_address = wallet_acc1.next_taproot_address().unwrap().to_string();
        let persistence_json = wallet_acc1.export_changeset().unwrap();
        let persistence_str = serde_json::to_string(&persistence_json).unwrap();

        // 3. Attempt to build "Account 0" using "Account 1" persistence
        // This simulates the bug: cached state from wrong account ID used for initialization
        let mut builder_acc0 = WalletBuilder::from_seed(network, Seed64::from_array(*seed));
        builder_acc0 = builder_acc0
            .with_account_index(0)
            .with_persistence(&persistence_str) // Inject mismatching persistence
            .unwrap();

        let mut wallet_acc0 = builder_acc0.build().unwrap();
        let acc0_address = wallet_acc0.next_taproot_address().unwrap().to_string();

        // 4. Verify:
        // - The resulting wallet should have Account 0's address (persistence ignored)
        // - It should NOT have Account 1's address
        assert_ne!(
            acc0_address, acc1_address,
            "Account 0 should have different address than Account 1"
        );

        // Let's create a pristine Account 0 to verify the address matches exactly
        let mut pristine_acc0 = WalletBuilder::from_seed(network, Seed64::from_array(*seed))
            .with_account_index(0)
            .build()
            .unwrap();
        let expected_acc0_addr = pristine_acc0.next_taproot_address().unwrap().to_string();

        assert_eq!(
            acc0_address, expected_acc0_addr,
            "Wallet should match clean Account 0 address, ignoring mismatched persistence"
        );
    }

    #[test]
    fn test_persistence_cycle_mismatch() {
        // This tests the "tpub vs xprv" descriptor string mismatch issue.
        // BDK persists as 'tpub' (checksummed), but we calculate 'xprv' (no checksum) on load.
        // The builder MUST be smart enough to load it anyway.

        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let network = Network::Regtest;

        // 1. Create original wallet
        let builder = WalletBuilder::from_seed(network, Seed64::from_array(*seed));
        let wallet = builder.build().unwrap();

        // Simulating some state to persist (would be empty changeset but structurally valid)
        let persistence_struct = wallet.export_changeset().unwrap();
        let persistence_str = serde_json::to_string(&persistence_struct).unwrap();

        // 2. Create NEW wallet with SAME seed + persistence
        let mut builder_rehydrated = WalletBuilder::from_seed(network, Seed64::from_array(*seed));
        builder_rehydrated = builder_rehydrated
            .with_persistence(&persistence_str)
            .unwrap();

        let res = builder_rehydrated.build();
        assert!(
            res.is_ok(),
            "Should build successfully with matching persistence"
        );

        let wallet_rehydrated = res.unwrap();

        // If hydration worked, the loaded changeset should be present (Some)
        // Note: Our builder returns a wallet struct. We can check internal state if exposed,
        // or rely on the fact that build() succeeded and didn't panic/fail.
        // The critical check is that `builder.rs` logic didn't reject the persistence
        // because of the string difference.

        assert!(
            wallet_rehydrated
                .loaded_vault_changeset
                .descriptor
                .is_some(),
            "Vault changeset descriptor should be loaded"
        );
    }

    #[test]
    fn test_set_active_account_resets_account_scoped_state() {
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let network = Network::Regtest;

        let mut wallet = WalletBuilder::from_seed(network, Seed64::from_array(*seed))
            .build()
            .unwrap();
        wallet.loaded_vault_changeset.network = Some(network);
        wallet.loaded_payment_changeset = Some(bdk_wallet::ChangeSet::default());
        wallet.inscribed_utxos.insert(bitcoin::OutPoint::null());
        wallet
            .inscriptions
            .push(crate::ordinals::types::Inscription {
                id: "testi0".to_string(),
                number: 1,
                satpoint: Default::default(),
                content_type: Some("image/png".to_string()),
                value: Some(1),
                content_length: None,
                timestamp: None,
            });
        wallet.ordinals_verified = true;
        let original_generation = wallet.account_generation;

        wallet.set_active_account(1).unwrap();

        assert_eq!(wallet.account_index, 1);
        assert!(wallet.loaded_vault_changeset.network.is_none());
        assert!(wallet.loaded_payment_changeset.is_none());
        assert!(wallet.inscribed_utxos.is_empty());
        assert!(wallet.inscriptions.is_empty());
        assert!(!wallet.ordinals_verified);
        assert_eq!(wallet.account_generation, original_generation + 1);
    }

    #[test]
    fn test_unverified_inscription_cache_does_not_mark_verified() {
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let network = Network::Regtest;

        let mut wallet = WalletBuilder::from_seed(network, Seed64::from_array(*seed))
            .build()
            .unwrap();

        let mut protected = std::collections::HashSet::new();
        protected.insert(bitcoin::OutPoint::null());
        wallet.apply_verified_ordinals_update(Vec::new(), protected);
        assert!(wallet.ordinals_verified);
        assert!(!wallet.inscribed_utxos.is_empty());

        let count =
            wallet.apply_unverified_inscriptions_cache(vec![crate::ordinals::types::Inscription {
                id: "testi0".to_string(),
                number: 1,
                satpoint: Default::default(),
                content_type: Some("image/png".to_string()),
                value: Some(1),
                content_length: None,
                timestamp: None,
            }]);

        assert_eq!(count, 1);
        assert_eq!(wallet.inscriptions.len(), 1);
        assert!(wallet.inscribed_utxos.is_empty());
        assert!(!wallet.ordinals_verified);
        assert!(wallet.ordinals_metadata_complete);
    }

    #[test]
    fn test_collect_active_addresses_returns_only_main_addresses() {
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(*seed))
            .with_scheme(AddressScheme::Dual)
            .build()
            .unwrap();

        let addresses = wallet.collect_active_addresses();
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], wallet.peek_taproot_address(0).to_string());
        assert_eq!(
            addresses[1],
            wallet
                .peek_payment_address(0)
                .expect("payment address")
                .to_string()
        );
    }

    #[test]
    fn test_prepare_requests_scans_only_external_index_zero() {
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(*seed))
            .with_scheme(AddressScheme::Dual)
            .build()
            .unwrap();

        let expected_taproot_spk = wallet.peek_taproot_address(0).script_pubkey();
        let expected_payment_spk = wallet
            .peek_payment_address(0)
            .expect("payment address")
            .script_pubkey();

        let requests = wallet.prepare_requests();
        match requests.taproot {
            SyncRequestType::Full(mut req) => {
                let keychains = req.keychains();
                assert_eq!(keychains, vec![KeychainKind::External]);
                let spks: Vec<_> = req.iter_spks(KeychainKind::External).collect();
                assert_eq!(spks.len(), 1);
                assert_eq!(spks[0].0, 0);
                assert_eq!(spks[0].1, expected_taproot_spk);
            }
            SyncRequestType::Incremental(_) => panic!("expected full scan request"),
        }

        match requests.payment {
            Some(SyncRequestType::Full(mut req)) => {
                let keychains = req.keychains();
                assert_eq!(keychains, vec![KeychainKind::External]);
                let spks: Vec<_> = req.iter_spks(KeychainKind::External).collect();
                assert_eq!(spks.len(), 1);
                assert_eq!(spks[0].0, 0);
                assert_eq!(spks[0].1, expected_payment_spk);
            }
            Some(SyncRequestType::Incremental(_)) => panic!("expected full scan request"),
            None => panic!("expected payment request in dual mode"),
        }
    }
}
