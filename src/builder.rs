//! Core wallet construction and stateful operations.
//!
//! This module contains the `WalletBuilder` entrypoint plus the primary
//! `ZincWallet` runtime used by both native Rust and WASM bindings.

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_chain::Merge;
use bdk_esplora::EsploraAsyncExt;

use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::address::{AddressType, NetworkUnchecked};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, Network, Transaction};
// use bitcoin::PsbtSighashType; // Failed
use crate::error::ZincError;
use crate::keys::ZincMnemonic;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const LOG_TARGET_BUILDER: &str = "zinc_core::builder";

/// Platform-safe current-time-in-seconds for BDK sync request start times.
///
/// `FullScanRequest::builder()` (the parameterless variant) calls
/// `std::time::UNIX_EPOCH.elapsed()` internally, which panics on
/// `wasm32-unknown-unknown` with "time not implemented on this platform".
/// This helper provides the same value via `js_sys::Date::now()` on WASM
/// and the standard library on native targets.
fn wasm_now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_secs()
    }
}

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

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Strongly-typed 64-byte seed material used by canonical constructors.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

/// Payment address branch type used in dual-scheme mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PaymentAddressType {
    /// BIP84 native segwit (bech32 `bc1q...` / `tb1q...`).
    #[default]
    NativeSegwit,
    /// BIP49 nested segwit (P2SH `3...` / `2...`).
    NestedSegwit,
    /// BIP44 legacy P2PKH (`1...` / `m|n...`).
    Legacy,
}

impl PaymentAddressType {
    #[must_use]
    pub fn purpose(self) -> u32 {
        match self {
            Self::NativeSegwit => 84,
            Self::NestedSegwit => 49,
            Self::Legacy => 44,
        }
    }
}

/// Logical account mapping mode for descriptor derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DerivationMode {
    /// Traditional account derivation: account=N, address index=0.
    #[default]
    Account,
    /// Index-style derivation: account=0, address index=N.
    Index,
}

/// Operational mode for the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// Full signing capabilities with stored seed.
    Seed,
    /// Watch-only mode (public descriptors only).
    Watch,
}

/// Controls for address discovery and sync behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanPolicy {
    /// Number of consecutive unused addresses to skip before stopping scan.
    pub account_gap_limit: u32,
    /// Constant number of addresses to scan regardless of activity.
    pub address_scan_depth: u32,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            account_gap_limit: 20,
            address_scan_depth: 1,
        }
    }
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

/// Represents the cryptographic identity of the wallet.
#[derive(Debug, Clone)]
pub enum WalletKind {
    /// Full signing capability with master private key.
    Seed {
        /// Master extended private key derived from the seed.
        master_xprv: bdk_wallet::bitcoin::bip32::Xpriv,
    },
    /// Hardware/watch-only wallet constructed from public descriptors.
    Hardware {
        /// The 4-byte master fingerprint of the hardware device.
        fingerprint: [u8; 4],
        /// External taproot descriptor for public key derivation.
        taproot_external: String,
        /// Optional external payment descriptor for public key derivation.
        payment_external: Option<String>,
    },
    /// Read-only capability bound to a single tracked address.
    WatchAddress(Address),
}

impl WalletKind {
    /// Returns true if this identity is read-only.
    #[must_use]
    pub fn is_watch(&self) -> bool {
        !matches!(self, Self::Seed { .. })
    }

    /// Derive external and internal descriptor strings for the vault and optional payment keychains.
    /// Returns (vault_external, vault_internal, payment_external, payment_internal).
    pub fn derive_descriptors(
        &self,
        scheme: AddressScheme,
        payment_type: PaymentAddressType,
        network: Network,
        account: u32,
    ) -> (String, String, Option<String>, Option<String>) {
        let coin_type = u32::from(network != Network::Bitcoin);

        match self {
            Self::Seed { master_xprv: master } => {
                let vault_ext = format!("tr({master}/86'/{coin_type}'/{account}'/0/*)");
                let vault_int = format!("tr({master}/86'/{coin_type}'/{account}'/1/*)");

                if scheme == AddressScheme::Dual {
                    let pay_ext =
                        payment_descriptor_for_xprv(master, payment_type, coin_type, account, 0);
                    let pay_int =
                        payment_descriptor_for_xprv(master, payment_type, coin_type, account, 1);
                    (vault_ext, vault_int, Some(pay_ext), Some(pay_int))
                } else {
                    (vault_ext, vault_int, None, None)
                }
            }
            Self::Hardware {
                taproot_external,
                payment_external,
                ..
            } => {
                // For hardware wallets, we assume the provided descriptors are already at the account level.
                (
                    taproot_external.clone(),
                    taproot_external.replace("/0/*", "/1/*"),
                    payment_external.clone(),
                    payment_external.as_ref().map(|e| e.replace("/0/*", "/1/*")),
                )
            }
            Self::WatchAddress(address) => {
                let descriptor = taproot_watch_descriptor(address)
                    .expect("watch-address identity must hold a validated taproot address");
                (descriptor.clone(), descriptor, None, None)
            }
        }
    }
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
    /// Account derivation mode.
    pub(crate) derivation_mode: DerivationMode,
    /// Payment branch address type (used in dual scheme).
    pub(crate) payment_address_type: PaymentAddressType,
    // Store original loaded changesets to merge with staged changes for full persistence
    /// Loaded taproot changeset baseline used for persistence merges.
    pub(crate) loaded_vault_changeset: bdk_wallet::ChangeSet,
    /// Loaded payment changeset baseline used for persistence merges.
    pub(crate) loaded_payment_changeset: Option<bdk_wallet::ChangeSet>,
    /// Active account index.
    pub(crate) account_index: u32,
    /// Whether the wallet has signing capabilities.
    pub(crate) mode: ProfileMode,
    /// Active scan policy for address discovery.
    pub(crate) scan_policy: ScanPolicy,
    // Ordinal Shield State (In-Memory Only)
    /// Outpoints currently marked as inscribed/protected.
    pub(crate) inscribed_utxos: std::collections::HashSet<bitcoin::OutPoint>,
    /// Cached inscription metadata known to the wallet.
    pub(crate) inscriptions: Vec<crate::ordinals::types::Inscription>,
    /// Cached read-only rune balances known to the wallet.
    pub(crate) rune_balances: Vec<crate::ordinals::types::RuneBalance>,
    /// Whether ordinals protection state is currently verified.
    pub(crate) ordinals_verified: bool,
    /// Whether inscription metadata refresh has completed.
    pub(crate) ordinals_metadata_complete: bool,
    /// Cryptographic identity of this wallet (Seed or Hardware).
    pub(crate) kind: WalletKind,
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
    /// Receive index used for taproot lookups in this logical account.
    pub taproot_receive_index: u32,
    /// Optional payment external descriptor template.
    pub payment_descriptor: Option<String>,
    /// Optional payment internal/change descriptor template.
    pub payment_change_descriptor: Option<String>,
    /// Optional payment public key.
    pub payment_public_key: Option<String>,
    /// Optional payment receive index used for lookups in this logical account.
    pub payment_receive_index: Option<u32>,
}

/// Precomputed account discovery context that avoids exposing raw keys externally.
#[derive(Debug, Clone)]
pub struct DiscoveryContext {
    /// Network for the descriptors in this context.
    pub network: Network,
    /// Address scheme for descriptors in this context.
    pub scheme: AddressScheme,
    /// Account derivation mode for descriptor/account mapping.
    pub derivation_mode: DerivationMode,
    /// Payment branch type for dual descriptors.
    pub payment_address_type: PaymentAddressType,
    /// Cryptographic identity used for derivation.
    pub kind: WalletKind,
    /// Account plans to evaluate.
    pub accounts: Vec<DiscoveryAccountPlan>,
    /// Guard flag used to prevent overlapping sync operations.
    pub is_syncing: bool,
    /// Monotonic generation used to invalidate stale async operations.
    pub account_generation: u64,
}

fn payment_descriptor_for_xprv(
    xprv: &bdk_wallet::bitcoin::bip32::Xpriv,
    address_type: PaymentAddressType,
    coin_type: u32,
    account: u32,
    chain: u32,
) -> String {
    let pay_purpose = address_type.purpose();

    match address_type {
        PaymentAddressType::NativeSegwit => {
            format!("wpkh({xprv}/{pay_purpose}'/{coin_type}'/{account}'/{chain}/*)")
        }
        PaymentAddressType::NestedSegwit => {
            format!("sh(wpkh({xprv}/{pay_purpose}'/{coin_type}'/{account}'/{chain}/*))")
        }
        PaymentAddressType::Legacy => {
            format!("pkh({xprv}/{pay_purpose}'/{coin_type}'/{account}'/{chain}/*)")
        }
    }
}

fn payment_descriptor_for_xpub(
    xpub: &bdk_wallet::bitcoin::bip32::Xpub,
    address_type: PaymentAddressType,
    chain: u32,
) -> String {
    match address_type {
        PaymentAddressType::NativeSegwit => format!("wpkh({xpub}/{chain}/*)"),
        PaymentAddressType::NestedSegwit => format!("sh(wpkh({xpub}/{chain}/*))"),
        PaymentAddressType::Legacy => format!("pkh({xpub}/{chain}/*)"),
    }
}

fn parse_extended_public_key(xpub: &str) -> Result<bdk_wallet::bitcoin::bip32::Xpub, String> {
    use bdk_wallet::bitcoin::bip32::Xpub;

    if let Ok(parsed) = Xpub::from_str(xpub) {
        return Ok(parsed);
    }

    let mut data = bdk_wallet::bitcoin::base58::decode_check(xpub)
        .map_err(|e| format!("Invalid extended public key: {e}"))?;
    if data.len() != 78 {
        return Err(format!(
            "Invalid extended public key payload length: {} (expected 78)",
            data.len()
        ));
    }

    let version: [u8; 4] = [data[0], data[1], data[2], data[3]];
    let normalized_version = match version {
        // mainnet xpub/ypub/zpub/Ypub/Zpub variants
        [0x04, 0x88, 0xB2, 0x1E]
        | [0x04, 0x9D, 0x7C, 0xB2]
        | [0x04, 0xB2, 0x47, 0x46]
        | [0x02, 0x95, 0xB4, 0x3F]
        | [0x02, 0xAA, 0x7E, 0xD3] => [0x04, 0x88, 0xB2, 0x1E],
        // testnet/signet tpub/upub/vpub/Upub/Vpub variants
        [0x04, 0x35, 0x87, 0xCF]
        | [0x04, 0x4A, 0x52, 0x62]
        | [0x04, 0x5F, 0x1C, 0xF6]
        | [0x02, 0x42, 0x89, 0xEF]
        | [0x02, 0x57, 0x54, 0x83] => [0x04, 0x35, 0x87, 0xCF],
        _ => {
            return Err(
                "Unsupported extended public key prefix (expected xpub/ypub/zpub/tpub/upub/vpub)"
                    .to_string(),
            );
        }
    };

    data[0..4].copy_from_slice(&normalized_version);
    Xpub::decode(&data).map_err(|e| format!("Invalid extended public key: {e}"))
}

fn taproot_output_key_from_address(
    address: &Address,
) -> Result<bitcoin::secp256k1::XOnlyPublicKey, String> {
    if address.address_type() != Some(AddressType::P2tr) {
        return Err(
            "Address watch mode currently supports taproot (bc1p/tb1p/bcrt1p) addresses only"
                .to_string(),
        );
    }

    let witness_program = address
        .witness_program()
        .ok_or_else(|| "Taproot address missing witness program".to_string())?;
    let key_bytes = witness_program.program().as_bytes();
    if key_bytes.len() != 32 {
        return Err(format!(
            "Invalid taproot witness program length: {}",
            key_bytes.len()
        ));
    }

    bitcoin::secp256k1::XOnlyPublicKey::from_slice(key_bytes)
        .map_err(|e| format!("Invalid taproot output key: {e}"))
}

fn taproot_watch_descriptor(address: &Address) -> Result<String, String> {
    let output_key = taproot_output_key_from_address(address)?;
    Ok(format!("tr({output_key})"))
}

/// Builder for constructing a `ZincWallet` from identity, network, and options.
#[derive(Clone)]
pub struct WalletBuilder {
    network: Network,
    kind: Option<WalletKind>,
    mode: ProfileMode,
    scheme: AddressScheme,
    derivation_mode: DerivationMode,
    payment_address_type: PaymentAddressType,
    persistence: Option<ZincPersistence>,
    account_index: u32,
    scan_policy: ScanPolicy,
}

impl ZincWallet {
    fn watched_address(&self) -> Option<&Address> {
        match &self.kind {
            WalletKind::WatchAddress(address) => Some(address),
            _ => None,
        }
    }

    pub fn derive_public_key_internal(
        &self,
        purpose: u32,
        _network: Network,
        account: u32,
        index: u32,
    ) -> Result<String, String> {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();

        match &self.kind {
            WalletKind::Seed { master_xprv } => {
                let network = self.vault_wallet.network();
                let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
                let chain = 0; // External

                let purpose_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(purpose).map_err(|e| format!("Invalid purpose index: {}", e))?;
                let coin_type_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(coin_type).map_err(|e| format!("Invalid coin_type index: {}", e))?;
                let account_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(account).map_err(|e| format!("Invalid account index: {}", e))?;
                let chain_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(chain).map_err(|e| format!("Invalid chain index: {}", e))?;
                let index_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(index).map_err(|e| format!("Invalid child index: {}", e))?;

                let derivation_path = [
                    purpose_cn,
                    coin_type_cn,
                    account_cn,
                    chain_cn,
                    index_cn,
                ];

                let child_xprv = master_xprv
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
            WalletKind::Hardware {
                taproot_external,
                payment_external,
                ..
            } => {
                // For hardware wallets, we derive from the provided public descriptors.
                // Desc format is usually like: tr([fp/path]xpub.../0/*)
                let desc_str = if purpose == 86 {
                    taproot_external
                } else {
                    payment_external
                        .as_ref()
                        .ok_or_else(|| "Payment descriptor missing for this hardware wallet".to_string())?
                };

                // 1. Extract the Xpub string from the descriptor.
                // Find either the character after ']' or the first '(' which starts the descriptor payload.
                let xpub_start_part = if let Some(pos) = desc_str.find(']') {
                    &desc_str[pos + 1..]
                } else if let Some(pos) = desc_str.find('(') {
                    &desc_str[pos + 1..]
                } else {
                    desc_str
                };

                // Find the first slash indicating the derivation path start from the xpub.
                // If no slash, use the whole string (it might be a plain xpub or have trailing descriptor syntax).
                let xpub_end_pos = xpub_start_part.find('/').unwrap_or(xpub_start_part.len());
                let xpub_str = xpub_start_part[..xpub_end_pos].trim_end_matches(')');

                // 2. Parse and derive.
                use bitcoin::bip32::{ChildNumber, Xpub};
                use std::str::FromStr;
                let xpub = Xpub::from_str(xpub_str)
                    .map_err(|e| format!("Failed to parse xpub from descriptor (part: {}): {}", xpub_str, e))?;

                let chain_cn = ChildNumber::from_normal_idx(0).map_err(|e| format!("Invalid chain index: {}", e))?;
                let index_cn = ChildNumber::from_normal_idx(index).map_err(|e| format!("Invalid child index: {}", e))?;

                // Derive /0/index (assuming external chain '0' matches our descriptors)
                let derived_xpub = xpub
                    .derive_pub(
                        &secp,
                        &[
                            chain_cn,
                            index_cn,
                        ],
                    )
                    .map_err(|e| format!("Failed to derive public key from xpub: {}", e))?;

                let public_key = derived_xpub.public_key;

                if purpose == 86 {
                    let (x_only, _parity) = public_key.x_only_public_key();
                    Ok(x_only.to_string())
                } else {
                    Ok(public_key.to_string())
                }
            }
            WalletKind::WatchAddress(address) => {
                if purpose != 86 {
                    return Err(ZincError::CapabilityMissing.to_string());
                }
                let output_key = taproot_output_key_from_address(address)
                    .map_err(|_| ZincError::CapabilityMissing.to_string())?;
                return Ok(output_key.to_string());
            }
        }
    }

    /// Return the cached inscriptions currently tracked by the wallet.
    #[must_use]
    pub fn inscriptions(&self) -> &[crate::ordinals::types::Inscription] {
        &self.inscriptions
    }

    /// Return the cached rune balances currently tracked by the wallet.
    #[must_use]
    pub fn rune_balances(&self) -> &[crate::ordinals::types::RuneBalance] {
        &self.rune_balances
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

    /// Return the active derivation mode.
    #[must_use]
    pub fn derivation_mode(&self) -> DerivationMode {
        self.derivation_mode
    }

    /// Return the profile mode (`seed` vs `watch`).
    #[must_use]
    pub fn profile_mode(&self) -> ProfileMode {
        self.mode
    }

    /// Return the active payment address type.
    #[must_use]
    pub fn payment_address_type(&self) -> PaymentAddressType {
        self.payment_address_type
    }

    fn logical_account_path(&self, logical_account_index: u32) -> (u32, u32) {
        match self.derivation_mode {
            DerivationMode::Account => (logical_account_index, 0),
            DerivationMode::Index => (0, logical_account_index),
        }
    }

    fn active_receive_index(&self) -> u32 {
        self.logical_account_path(self.account_index).1
    }

    fn active_derivation_account(&self) -> u32 {
        self.logical_account_path(self.account_index).0
    }

    fn dual_payment_purpose(&self) -> u32 {
        self.payment_address_type.purpose()
    }

    /// Return `true` when wallet state indicates a full scan is needed.
    pub fn needs_full_scan(&self) -> bool {
        // If we have no transactions and the tip is at genesis (or missing), we likely need a full scan
        self.vault_wallet.local_chain().tip().height() == 0
    }

    /// Reveal and return the next taproot receive address.
    pub fn next_taproot_address(&mut self) -> Result<Address, String> {
        if let Some(address) = self.watched_address() {
            return Ok(address.clone());
        }

        if self.derivation_mode == DerivationMode::Index {
            return Ok(self.peek_taproot_address(0));
        }
        let info = self
            .vault_wallet
            .reveal_next_address(KeychainKind::External);
        Ok(info.address)
    }

    /// Peek a taproot receive address at `index` without advancing state.
    pub fn peek_taproot_address(&self, index: u32) -> Address {
        if let Some(address) = self.watched_address() {
            let _ = index;
            return address.clone();
        }

        let resolved_index = self.active_receive_index().saturating_add(index);
        self.vault_wallet
            .peek_address(KeychainKind::External, resolved_index)
            .address
    }

    /// Reveal and return the next payment address in dual mode.
    ///
    /// In unified mode this returns the next taproot address.
    pub fn get_payment_address(&mut self) -> Result<bitcoin::Address, String> {
        if self.scheme == AddressScheme::Dual {
            if self.derivation_mode == DerivationMode::Index {
                return self
                    .peek_payment_address(0)
                    .ok_or_else(|| "Payment wallet not initialized".to_string());
            }
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
            let resolved_index = self.active_receive_index().saturating_add(index);
            self.payment_wallet.as_ref().map(|w| {
                w.peek_address(KeychainKind::External, resolved_index)
                    .address
            })
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
        let now = wasm_now_secs();
        let vault = SyncRequestType::Full(Self::flexible_full_scan_request(
            &self.vault_wallet,
            self.scan_policy,
            now,
        ));

        let payment = self
            .payment_wallet
            .as_ref()
            .map(|w| SyncRequestType::Full(Self::flexible_full_scan_request(w, self.scan_policy, now)));

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
            all_events.push(format!("taproot:{event:?}"));
        }

        // 2. Apply Payment Update
        if let (Some(w), Some(u)) = (&mut self.payment_wallet, payment_update) {
            let payment_events = w.apply_update_events(u).map_err(|e| e.to_string())?;
            for event in payment_events {
                all_events.push(format!("payment:{event:?}"));
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
        let network = self.vault_wallet.network();
        self.vault_wallet = if matches!(&self.kind, WalletKind::WatchAddress(_)) {
            Wallet::create_single(vault_desc)
                .network(network)
                .create_wallet_no_persist()
                .map_err(|e| format!("Failed to reset taproot wallet: {e}"))?
        } else {
            let vault_change_desc = self
                .vault_wallet
                .public_descriptor(KeychainKind::Internal)
                .to_string();
            Wallet::create(vault_desc, vault_change_desc)
                .network(network)
                .create_wallet_no_persist()
                .map_err(|e| format!("Failed to reset taproot wallet: {e}"))?
        };
        self.loaded_vault_changeset = bdk_wallet::ChangeSet::default();

        // 2. Reset Payment Wallet (if exists)
        if let Some(w) = &self.payment_wallet {
            let pay_desc = w.public_descriptor(KeychainKind::External).to_string();
            let pay_change_desc = w.public_descriptor(KeychainKind::Internal).to_string();

            self.payment_wallet = Some(
                Wallet::create(pay_desc, pay_change_desc)
                    .network(network)
                    .create_wallet_no_persist()
                    .map_err(|e| format!("Failed to reset payment wallet: {e}"))?,
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
            .map_err(|e| format!("{e:?}"))?;

        let now = wasm_now_secs();
        let vault_req = Self::flexible_full_scan_request(&self.vault_wallet, self.scan_policy, now);
        let payment_req = self
            .payment_wallet
            .as_ref()
            .map(|w| Self::flexible_full_scan_request(w, self.scan_policy, now));

        let stop_gap = self.scan_policy.account_gap_limit as usize;
        let parallel_requests = 5;

        // 1. Sync Vault
        let vault_update = client
            .full_scan(vault_req, stop_gap, parallel_requests)
            .await
            .map_err(|e| e.to_string())?;

        // 2. Sync Payment (if exists)
        let payment_update = if let Some(req) = payment_req {
            Some(
                client
                    .full_scan(req, stop_gap, parallel_requests)
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
    /// Collect the wallet's main receive addresses for ordinals sync.
    ///
    /// The scan policy determines how many addresses are checked:
    /// - `address_scan_depth`: Ensuring at least N addresses are scanned.
    /// - Discovered active addresses from incremental sync.
    pub fn collect_active_addresses(&self) -> Vec<String> {
        if let Some(address) = self.watched_address() {
            return vec![address.to_string()];
        }

        let mut addresses = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut collect_from_wallet = |wallet: &Wallet| {
            // 1. Always include up to address_scan_depth
            for i in 0..self.scan_policy.address_scan_depth {
                let addr = wallet
                    .peek_address(KeychainKind::External, i)
                    .address
                    .to_string();
                if seen.insert(addr.clone()) {
                    addresses.push(addr);
                }
            }

            // 2. Include any addresses that have been discovered via sync/reveal
            // (e.g. if the user manually revealed address 5, or sync found funds there)
            for info in wallet.list_unused_addresses(KeychainKind::External) {
                let addr = info.address.to_string();
                if seen.insert(addr.clone()) {
                    addresses.push(addr);
                }
            }
        };

        collect_from_wallet(&self.vault_wallet);
        if let Some(w) = &self.payment_wallet {
            collect_from_wallet(w);
        }

        addresses
    }

    /// Update the wallet's internal inscription state.
    /// Call this AFTER fetching inscriptions successfully.
    pub fn apply_verified_ordinals_update(
        &mut self,
        inscriptions: Vec<crate::ordinals::types::Inscription>,
        protected_outpoints: std::collections::HashSet<bitcoin::OutPoint>,
        rune_balances: Vec<crate::ordinals::types::RuneBalance>,
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
        self.rune_balances = rune_balances;
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
        self.rune_balances.clear();
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
                "Ord Indexer is lagging! Ord: {ord_height}, Wallet: {wallet_height}. Safety lock engaged."
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
                .map_err(|e| format!("Failed to fetch for {addr_str}: {e}"))?;

            let protected = client
                .get_protected_outpoints_from_outputs(&snapshot.outputs)
                .await
                .map_err(|e| format!("Failed to fetch protected outputs for {addr_str}: {e}"))?;
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
        let rune_balances = client
            .get_rune_balances_for_addresses(&addresses)
            .await
            .map_err(|e| format!("Failed to fetch rune balances: {e}"))?;

        let mut all_inscriptions = Vec::new();
        for addr_str in addresses {
            let snapshot = client
                .get_address_asset_snapshot(&addr_str)
                .await
                .map_err(|e| format!("Failed to fetch for {addr_str}: {e}"))?;

            for inscription_id in snapshot.inscription_ids {
                let inscription = client
                    .get_inscription_details(&inscription_id)
                    .await
                    .map_err(|e| format!("Failed to fetch details for {inscription_id}: {e}"))?;
                all_inscriptions.push(inscription);
            }
        }

        self.inscriptions = all_inscriptions;
        self.rune_balances = rune_balances;
        self.ordinals_metadata_complete = true;
        Ok(self.inscriptions.len())
    }

    /// Sync Ordinals (Inscriptions) to build the Shield logic.
    /// This keeps the legacy behavior by running protection and metadata refresh.
    pub async fn sync_ordinals(&mut self, ord_url: &str) -> Result<usize, String> {
        self.sync_ordinals_protection(ord_url).await?;
        self.sync_ordinals_metadata(ord_url).await
    }

    /// Return account summaries for the active wallet.
    pub fn get_accounts(&self, count: u32) -> Vec<Account> {
        match &self.kind {
            WalletKind::WatchAddress(address) => {
                let taproot_address = address.to_string();
                let taproot_public_key = self.get_taproot_public_key(0).unwrap_or_default();
                vec![Account {
                    index: self.account_index,
                    label: format!("Account {}", self.account_index + 1),
                    taproot_address: taproot_address.clone(),
                    taproot_public_key: taproot_public_key.clone(),
                    payment_address: Some(taproot_address),
                    payment_public_key: Some(taproot_public_key),
                }]
            }
            WalletKind::Hardware { .. } => {
                let taproot_address = self.peek_taproot_address(0).to_string();
                let taproot_public_key = self.get_taproot_public_key(0).unwrap_or_default();
                let (payment_address, payment_public_key) = if self.scheme == AddressScheme::Dual {
                    (
                        self.peek_payment_address(0).map(|a| a.to_string()),
                        self.get_payment_public_key(0).ok(),
                    )
                } else {
                    (Some(taproot_address.clone()), Some(taproot_public_key.clone()))
                };
                vec![Account {
                    index: self.account_index,
                    label: format!("Account {}", self.account_index + 1),
                    taproot_address,
                    taproot_public_key,
                    payment_address,
                    payment_public_key,
                }]
            }
            WalletKind::Seed { master_xprv } => {
                let mut accounts = Vec::new();
                for i in 0..count {
                    // Temporarily build a builder to derive addresses for other accounts
                    let builder = WalletBuilder::new(self.vault_wallet.network())
                        .kind(WalletKind::Seed {
                            master_xprv: *master_xprv,
                        })
                        .with_scheme(self.scheme)
                        .with_derivation_mode(self.derivation_mode)
                        .with_payment_address_type(self.payment_address_type)
                        .with_account_index(i);

                    if let Ok(zwallet) = builder.build() {
                        let taproot_address = zwallet.peek_taproot_address(0).to_string();
                        let taproot_public_key = zwallet.get_taproot_public_key(0).unwrap_or_default();
                        let (payment_address, payment_public_key) = if self.scheme == AddressScheme::Dual {
                            (
                                zwallet.peek_payment_address(0).map(|a| a.to_string()),
                                zwallet.get_payment_public_key(0).ok(),
                            )
                        } else {
                            (Some(taproot_address.clone()), Some(taproot_public_key.clone()))
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
        }
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

        let active_receive_index = self.active_receive_index();
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
            .peek_address(KeychainKind::External, active_receive_index)
            .script_pubkey();

        let mut builder = wallet.build_tx();
        if !self.inscribed_utxos.is_empty() {
            builder.unspendable(self.inscribed_utxos.iter().copied().collect());
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
        let should_finalize = options.as_ref().is_some_and(|o| o.finalize);
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
                let target_sighash =
                    bitcoin::psbt::PsbtSighashType::from_u32(u32::from(sighash_u8));
                for input in &mut psbt.inputs {
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
                        "Security Violation: sign_inputs index {index} is duplicated"
                    ));
                }
                let input = &psbt.inputs[*index];
                if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                    return Err(format!(
                        "Security Violation: Requested input #{index} is missing UTXO metadata"
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
                        "Security Violation: Sighash type is not allowed on input #{index} (value={value})"
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
            return Err(format!("Security Violation: {e}"));
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
                        "Security Violation: Requested input #{index} was not signed by this wallet"
                    ));
                }
            }
        }

        // Validation: Verify all requested inputs were signed

        let signed_bytes = psbt.serialize();
        let signed_base64 = base64::engine::general_purpose::STANDARD.encode(&signed_bytes);

        Ok(signed_base64)
    }

    /// Prepare a PSBT for external signing (e.g. on a hardware wallet).
    ///
    /// Performs the pre-sign checks and enrichment that `sign_psbt` does
    /// (UTXO enrichment, sighash validation, bounds checks, Ordinal Shield),
    /// then returns the enriched PSBT as base64 for device signing.
    pub fn prepare_external_sign_psbt(
        &self,
        psbt_base64: &str,
        options: Option<SignOptions>,
    ) -> Result<String, String> {
        use base64::Engine;

        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_base64)
            .map_err(|e| format!("Invalid base64: {e}"))?;

        let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| format!("Invalid PSBT: {e}"))?;

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

        #[allow(deprecated)]
        let _ = self.vault_wallet.sign(&mut psbt, bdk_wallet::SignOptions::default());
        if let Some(w) = &self.payment_wallet {
            #[allow(deprecated)]
            let _ = w.sign(&mut psbt, bdk_wallet::SignOptions::default());
        }

        if let Some(opts) = &options {
            if let Some(sighash_u8) = opts.sighash {
                let target_sighash = bitcoin::psbt::PsbtSighashType::from_u32(sighash_u8 as u32);
                for input in psbt.inputs.iter_mut() {
                    input.sighash_type = Some(target_sighash);
                }
            }
        }

        let inputs_to_sign = options.as_ref().and_then(|o| o.sign_inputs.clone());
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

        let mut known_inscriptions: HashMap<(bitcoin::Txid, u32), Vec<(String, u64)>> =
            HashMap::new();
        for ins in &self.inscriptions {
            known_inscriptions
                .entry((ins.satpoint.outpoint.txid, ins.satpoint.outpoint.vout))
                .or_default()
                .push((ins.id.clone(), ins.satpoint.offset));
        }
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

        let prepared_bytes = psbt.serialize();
        Ok(base64::engine::general_purpose::STANDARD.encode(&prepared_bytes))
    }

    /// Verify a PSBT that was signed externally (e.g. by a hardware wallet).
    ///
    /// Ensures unsigned transaction bytes are unchanged and only expected inputs
    /// gained signatures, then optionally finalizes and returns base64.
    pub fn verify_external_signed_psbt(
        &self,
        original_psbt_base64: &str,
        signed_psbt_base64: &str,
        required_input_indices: Option<&[usize]>,
        finalize: bool,
    ) -> Result<String, String> {
        use base64::Engine;
        use bitcoin::consensus::Encodable;

        let decode = |b64: &str, label: &str| -> Result<Psbt, String> {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 in {label}: {e}"))?;
            Psbt::deserialize(&bytes).map_err(|e| format!("Invalid PSBT in {label}: {e}"))
        };

        let original = decode(original_psbt_base64, "original")?;
        let mut signed = decode(signed_psbt_base64, "signed")?;

        let mut orig_tx_bytes = Vec::new();
        original
            .unsigned_tx
            .consensus_encode(&mut orig_tx_bytes)
            .map_err(|e| format!("Failed to encode original tx: {e}"))?;

        let mut signed_tx_bytes = Vec::new();
        signed
            .unsigned_tx
            .consensus_encode(&mut signed_tx_bytes)
            .map_err(|e| format!("Failed to encode signed tx: {e}"))?;

        if orig_tx_bytes != signed_tx_bytes {
            return Err(
                "Security Violation: Device returned a PSBT with a modified transaction. \
                 The unsigned_tx bytes do not match the original."
                    .to_string(),
            );
        }

        let check_indices: Vec<usize> = required_input_indices
            .map(|v| v.to_vec())
            .unwrap_or_else(|| (0..signed.inputs.len()).collect());

        for &idx in &check_indices {
            if idx >= signed.inputs.len() {
                return Err(format!(
                    "Security Violation: required input index {} is out of bounds",
                    idx
                ));
            }

            let input = &signed.inputs[idx];
            let has_signature = input.tap_key_sig.is_some()
                || !input.tap_script_sigs.is_empty()
                || !input.partial_sigs.is_empty()
                || input.final_script_witness.is_some();

            if !has_signature {
                return Err(format!(
                    "Security Violation: Required input #{} was not signed by the device",
                    idx
                ));
            }
        }

        if required_input_indices.is_some() {
            let required_set: std::collections::HashSet<usize> =
                check_indices.iter().copied().collect();

            for (i, (orig_input, signed_input)) in original
                .inputs
                .iter()
                .zip(signed.inputs.iter())
                .enumerate()
            {
                if required_set.contains(&i) {
                    continue;
                }

                let signatures_changed = orig_input.tap_key_sig != signed_input.tap_key_sig
                    || orig_input.tap_script_sigs != signed_input.tap_script_sigs
                    || orig_input.partial_sigs != signed_input.partial_sigs
                    || orig_input.final_script_witness != signed_input.final_script_witness;

                if signatures_changed {
                    return Err(format!(
                        "Security Violation: Input #{} received an unauthorized signature \
                         (not in required_input_indices)",
                        i
                    ));
                }
            }
        }

        if !finalize {
            // External multi-pass hardware signing can reuse the signed PSBT as input
            // for a subsequent pass (e.g. payment first, then taproot). Some device
            // SDKs infer "internal" inputs from derivation metadata and can be
            // confused by derivations added in prior passes. Clearing derivation
            // metadata here keeps the collected signatures while preventing
            // cross-pass account-type contamination.
            for input in signed.inputs.iter_mut() {
                input.bip32_derivation.clear();
                input.tap_key_origins.clear();
            }
        }

        if finalize {
            for input in signed.inputs.iter_mut() {
                if let Some(sig) = input.tap_key_sig {
                    let mut witness = bitcoin::Witness::new();
                    witness.push(sig.to_vec());
                    input.final_script_witness = Some(witness);
                    input.tap_key_sig = None;
                    input.tap_internal_key = None;
                    input.tap_merkle_root = None;
                    input.tap_key_origins.clear();
                    input.witness_utxo = None;
                    input.sighash_type = None;
                } else if !input.partial_sigs.is_empty() {
                    if let Some((pubkey, sig)) = input.partial_sigs.iter().next() {
                        let mut witness = bitcoin::Witness::new();
                        witness.push(sig.to_vec());
                        witness.push(pubkey.to_bytes());
                        input.final_script_witness = Some(witness);
                        input.partial_sigs.clear();
                        input.bip32_derivation.clear();
                        input.witness_utxo = None;
                        input.sighash_type = None;
                    }
                }
            }
        }

        let verified_bytes = signed.serialize();
        Ok(base64::engine::general_purpose::STANDARD.encode(&verified_bytes))
    }

    /// Analyzes a PSBT for Ordinal Shield protection.
    /// Returns a JSON string containing the `AnalysisResult`.
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

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                let outpoint = psbt.unsigned_tx.input[i].previous_output;
                if let Some(txout) = known_utxos.get(&outpoint) {
                    input.witness_utxo = Some(txout.clone());
                }
            }
        }

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
    /// Supports both Vault (Taproot) and Payment (`SegWit`) addresses.
    pub fn sign_message(&self, address: &str, message: &str) -> Result<String, String> {
        use base64::Engine;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Message, Secp256k1};

        if let Some(watched) = self.watched_address() {
            if watched.to_string() == address {
                let _ = message;
                return Err(ZincError::CapabilityMissing.to_string());
            }
        }

        // 1. Identify which wallet/keychain owns this address
        let active_receive_index = self.active_receive_index();
        let vault_addr = self
            .vault_wallet
            .peek_address(KeychainKind::External, active_receive_index)
            .address
            .to_string();

        let (is_vault, is_payment) = if address == vault_addr {
            (true, false)
        } else if let Some(w) = &self.payment_wallet {
            let pay_addr = w
                .peek_address(KeychainKind::External, active_receive_index)
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
        // Derivation path components
        let (purpose, chain) = if is_vault {
            (86, 0)
        } else {
            (self.dual_payment_purpose(), 0)
        };
        let priv_key = self.derive_private_key(purpose, chain, 0)
            .map_err(|_| ZincError::CapabilityMissing.to_string())?;

        // 3. Sign Message
        let signature_hash = bitcoin::sign_message::signed_msg_hash(message);
        let msg = Message::from_digest(signature_hash.to_byte_array());

        let sig = secp.sign_ecdsa_recoverable(&msg, &priv_key);
        let (rec_id, sig_bytes_compact) = sig.serialize_compact();

        let mut header = 27 + u8::try_from(rec_id.to_i32()).unwrap();
        header += 4; // Always compressed

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.push(header);
        sig_bytes.extend_from_slice(&sig_bytes_compact);

        Ok(base64::engine::general_purpose::STANDARD.encode(&sig_bytes))
    }

    /// Derive the pairing signer secret key hex for this account.
    ///
    /// Uses the first taproot external key path: `m/86'/coin'/account'/0/0`.
    pub fn get_pairing_secret_key_hex(&self) -> Result<String, String> {
        let key = self.derive_private_key(86, 0, 0)?;
        Ok(bytes_to_lower_hex(&key.secret_bytes()))
    }
    /// Derive the taproot public key for this account at `index`.
    pub fn get_taproot_public_key(&self, index: u32) -> Result<String, String> {
        self.derive_public_key(86, index)
    }

    /// Derive the payment public key for this account at `index`.
    ///
    /// In unified mode this uses the same key family as taproot.
    pub fn get_payment_public_key(&self, index: u32) -> Result<String, String> {
        // Dual uses the selected payment family, unified mirrors taproot.
        let purpose = if self.scheme == AddressScheme::Dual {
            self.dual_payment_purpose()
        } else {
            86
        };
        self.derive_public_key(purpose, index)
    }

    fn derive_public_key(&self, purpose: u32, index: u32) -> Result<String, String> {
        let account = self.active_derivation_account();
        let effective_index = self.active_receive_index().saturating_add(index);
        self.derive_public_key_internal(purpose, self.vault_wallet.network(), account, effective_index)
    }

    fn derive_private_key(&self, purpose: u32, chain: u32, index: u32) -> Result<bitcoin::secp256k1::SecretKey, String> {
        let account = self.active_derivation_account();
        let effective_index = self.active_receive_index().saturating_add(index);
        self.derive_private_key_internal(purpose, account, chain, effective_index)
    }

    fn derive_private_key_internal(
        &self,
        purpose: u32,
        account: u32,
        chain: u32,
        index: u32,
    ) -> Result<bitcoin::secp256k1::SecretKey, String> {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();

        match &self.kind {
            WalletKind::Seed { master_xprv } => {
                let network = self.vault_wallet.network();
                let coin_type = u32::from(network != Network::Bitcoin);

                let purpose_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(purpose).map_err(|e| format!("Invalid purpose index: {}", e))?;
                let coin_type_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(coin_type).map_err(|e| format!("Invalid coin_type index: {}", e))?;
                let account_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(account).map_err(|e| format!("Invalid account index: {}", e))?;
                let chain_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(chain).map_err(|e| format!("Invalid chain index: {}", e))?;
                let index_cn = bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(index).map_err(|e| format!("Invalid child index: {}", e))?;

                let derivation_path = [
                    purpose_cn,
                    coin_type_cn,
                    account_cn,
                    chain_cn,
                    index_cn,
                ];

                let child_xprv = master_xprv
                    .derive_priv(&secp, &derivation_path)
                    .map_err(|e| format!("Key derivation failed: {e}"))?;

                Ok(child_xprv.private_key)
            }
            _ => Err("Private key derivation not supported for this wallet kind".to_string()),
        }
    }

    fn sign_inscription_script_paths(
        &self,
        psbt: &mut Psbt,
        finalize: bool,
        indices: Option<&[usize]>,
    ) -> Result<(), String> {
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::sighash::{Prevouts, SighashCache};

        let secp = Secp256k1::new();
        let network = self.vault_wallet.network();

        // 1. Collect all prevouts for sighash calculation
        let mut prevouts = Vec::with_capacity(psbt.unsigned_tx.input.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .or_else(|| input.non_witness_utxo.as_ref().and_then(|tx| tx.output.get(psbt.unsigned_tx.input[i].previous_output.vout as usize)))
                .ok_or_else(|| format!("Missing witness_utxo for input #{i}"))?;
            prevouts.push(utxo.clone());
        }
        let prevouts_all = Prevouts::All(&prevouts);

        // 2. Iterate inputs and sign matches
        for i in 0..psbt.inputs.len() {
            if let Some(allowed) = indices {
                if !allowed.contains(&i) {
                    continue;
                }
            }

            let input = &mut psbt.inputs[i];
            if input.tap_key_sig.is_some() || !input.tap_script_sigs.is_empty() {
                continue; // Already signed
            }

            // Check if this is an inscription reveal (tap_key_origins with empty fingerprint)
            let mut key_found = false;
            for (pubkey, (_, origin)) in &input.tap_key_origins {
                // Heuristic: Reveal inputs use the internal key directly in the script path
                // and often have an empty fingerprint [0,0,0,0] in the PSBT origin.
                if *origin.0.as_bytes() == [0, 0, 0, 0] {
                    // Try to derive the ordinals key (m/86'/coin'/account'/0/0)
                    let account = self.active_derivation_account();
                    let effective_index = self.active_receive_index();
                    if let Ok(derived_pubkey_hex) = self.derive_public_key_internal(86, network, account, effective_index) {
                        if pubkey.to_string() == derived_pubkey_hex {
                            // MATCH! Sign it.
                            let priv_key = self.derive_private_key(86, 0, 0)?;
                            
                            let mut cache = SighashCache::new(&psbt.unsigned_tx);
                            let sighash_type = input.sighash_type.unwrap_or(bitcoin::psbt::PsbtSighashType::from_u32(0)); // DEFAULT
                            
                            // For reveal, we sign the script path.
                            for (_control_block, (script, _)) in &input.tap_scripts {
                                let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(script, bitcoin::taproot::LeafVersion::TapScript);

                                // Convert PsbtSighashType to TapSighashType
                                let tap_sighash_type = match sighash_type.to_u32() {
                                    0 => bitcoin::sighash::TapSighashType::Default,
                                    1 => bitcoin::sighash::TapSighashType::All,
                                    2 => bitcoin::sighash::TapSighashType::None,
                                    3 => bitcoin::sighash::TapSighashType::Single,
                                    0x81 => bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
                                    0x82 => bitcoin::sighash::TapSighashType::NonePlusAnyoneCanPay,
                                    0x83 => bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
                                    _ => bitcoin::sighash::TapSighashType::Default,
                                };

                                let sighash = cache
                                    .taproot_script_spend_signature_hash(
                                        i,
                                        &prevouts_all,
                                        leaf_hash,
                                        tap_sighash_type,
                                    )
                                    .map_err(|e| format!("Sighash calculation failed: {e}"))?;

                                let msg = Message::from_digest(sighash.to_byte_array());
                                let sig = secp.sign_schnorr(&msg, &priv_key.keypair(&secp));
                                
                                let mut final_sig = sig.as_ref().to_vec();
                                if tap_sighash_type != bitcoin::sighash::TapSighashType::Default {
                                    final_sig.push(tap_sighash_type as u8);
                                }
                                
                                input.tap_script_sigs.insert((*pubkey, leaf_hash), bitcoin::taproot::Signature::from_slice(&final_sig).unwrap());
                                key_found = true;
                            }
                        }
                    }
                }
            }

            if key_found && finalize {
                // Note: Full script-path finalization is complex (needs script + control block).
                // We leave it to the dApp or BDK if possible, or implement minimal reveal finalizer here.
            }
        }

        Ok(())
    }

    /// Return recently revealed addresses for the given keychain.
    pub fn get_revealed_addresses(&self, keychain: KeychainKind) -> Vec<String> {
        let wallet = match keychain {
            KeychainKind::External => &self.vault_wallet,
            KeychainKind::Internal => &self.vault_wallet,
        };
        wallet
            .list_unused_addresses(keychain)
            .into_iter()
            .map(|info| info.address.to_string())
            .collect()
    }

    fn flexible_full_scan_request(
        wallet: &Wallet,
        policy: ScanPolicy,
        now: u64,
    ) -> FullScanRequest<KeychainKind> {
        // IMPORTANT: use the explicit `start_time` variant to avoid
        // std time calls that panic on wasm32-unknown-unknown.
        let mut builder = wallet.start_full_scan_at(now);

        // 1. Set explicit scan depth (always scan at least N)
        if policy.address_scan_depth > 0 {
            for keychain in [KeychainKind::External, KeychainKind::Internal] {
                // Eagerly collect to satisfy 'static bound on iterator in BDK builder
                let spks: Vec<(u32, bitcoin::ScriptBuf)> = (0..policy.address_scan_depth)
                    .map(|i| (i, wallet.peek_address(keychain, i).script_pubkey()))
                    .collect();
                builder = builder.spks_for_keychain(keychain, spks);
            }
        }

        builder.build()
    }
}

/// Builder for constructing a `ZincWallet` from identity, network, and options.
impl WalletBuilder {
    /// Create a new builder for the specified network.
    #[must_use]
    pub fn new(network: Network) -> Self {
        Self {
            network,
            kind: None,
            mode: ProfileMode::Seed,
            scheme: AddressScheme::Unified,
            derivation_mode: DerivationMode::Account,
            payment_address_type: PaymentAddressType::NativeSegwit,
            persistence: None,
            account_index: 0,
            scan_policy: ScanPolicy::default(),
        }
    }

    /// Shortcut for creating a builder from a mnemonic phrase.
    pub fn from_mnemonic(network: Network, mnemonic: &ZincMnemonic) -> Self {
        use bdk_wallet::bitcoin::bip32::Xpriv;
        let seed = mnemonic.to_seed("");
        let master_xprv = Xpriv::new_master(network, seed.as_ref()).expect("valid seed");
        Self::new(network).kind(WalletKind::Seed { master_xprv })
    }

    /// Shortcut for creating a builder from a seed (used by discovery).
    pub fn from_seed(network: Network, seed: Seed64) -> Self {
        use bdk_wallet::bitcoin::bip32::Xpriv;
        let master_xprv = Xpriv::new_master(network, seed.as_ref()).expect("valid seed");
        Self::new(network).kind(WalletKind::Seed { master_xprv })
    }

    /// Shortcut for creating a builder for watch-only profiles.
    pub fn from_watch_only(network: Network) -> Self {
        Self::new(network).mode(ProfileMode::Watch)
    }

    /// Set the watch address for single-address watch profiles.
    pub fn with_watch_address(mut self, address: &str) -> Result<Self, String> {
        let addr = address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| format!("Invalid address: {e}"))?
            .require_network(self.network)
            .map_err(|e| format!("Network mismatch: {e}"))?;

        if addr.address_type() != Some(AddressType::P2tr) {
            return Err(
                "Address watch mode currently supports taproot (bc1p/tb1p/bcrt1p) addresses only"
                    .to_string(),
            );
        }

        self.kind = Some(WalletKind::WatchAddress(addr));
        Ok(self)
    }

    /// Set the account xpub for watch-only profiles.
    pub fn with_xpub(mut self, xpub: &str) -> Result<Self, String> {
        let parsed = parse_extended_public_key(xpub)?;
        let taproot_desc = format!("tr({parsed}/0/*)");
        let payment_desc = payment_descriptor_for_xpub(&parsed, self.payment_address_type, 0);
        self.kind = Some(WalletKind::Hardware {
            fingerprint: [0, 0, 0, 0],
            taproot_external: taproot_desc,
            payment_external: Some(payment_desc),
        });
        Ok(self)
    }

    /// Set the explicit taproot account xpub for dual-account watch profiles.
    pub fn with_taproot_xpub(mut self, xpub: &str) -> Result<Self, String> {
        let parsed = parse_extended_public_key(xpub)?;
        let taproot_desc = format!("tr({parsed}/0/*)");
        
        let mut kind = self.kind.take().unwrap_or(WalletKind::Hardware {
            fingerprint: [0, 0, 0, 0],
            taproot_external: String::new(),
            payment_external: None,
        });

        if let WalletKind::Hardware { ref mut taproot_external, .. } = kind {
            *taproot_external = taproot_desc;
        }
        
        self.kind = Some(kind);
        Ok(self)
    }

    /// Set the explicit payment account xpub for dual-account watch profiles.
    pub fn with_payment_xpub(mut self, xpub: &str) -> Result<Self, String> {
        let parsed = parse_extended_public_key(xpub)?;
        let payment_desc = payment_descriptor_for_xpub(&parsed, self.payment_address_type, 0);
        
        let mut kind = self.kind.take().unwrap_or(WalletKind::Hardware {
            fingerprint: [0, 0, 0, 0],
            taproot_external: String::new(),
            payment_external: None,
        });

        if let WalletKind::Hardware { ref mut payment_external, .. } = kind {
            *payment_external = Some(payment_desc);
        }
        
        self.kind = Some(kind);
        Ok(self)
    }

    /// Set the wallet's cryptographic identity.
    #[must_use]
    pub fn kind(mut self, kind: WalletKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Set the operational mode (`seed` vs `watch`).
    #[must_use]
    pub fn mode(mut self, mode: ProfileMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the address scheme (`unified` vs `dual`).
    #[must_use]
    pub fn with_scheme(mut self, scheme: AddressScheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Set the account derivation mode (`account` vs `index`).
    #[must_use]
    pub fn with_derivation_mode(mut self, mode: DerivationMode) -> Self {
        self.derivation_mode = mode;
        self
    }

    /// Set the payment address type for dual-scheme wallets.
    #[must_use]
    pub fn with_payment_address_type(mut self, address_type: PaymentAddressType) -> Self {
        self.payment_address_type = address_type;
        self
    }

    /// Set the account index to use for derivation.
    #[must_use]
    pub fn with_account_index(mut self, index: u32) -> Self {
        self.account_index = index;
        self
    }

    /// Set the scan policy for address discovery.
    #[must_use]
    pub fn scan_policy(mut self, policy: ScanPolicy) -> Self {
        self.scan_policy = policy;
        self
    }

    /// Set the persistence snapshot to load.
    pub fn with_persistence(mut self, persistence_json: &str) -> Result<Self, String> {
        let persistence: ZincPersistence = serde_json::from_str(persistence_json)
            .map_err(|e| format!("Failed to parse persistence JSON: {e}"))?;
        self.persistence = Some(persistence);
        Ok(self)
    }

    /// Set the persistence snapshot to load directly.
    #[must_use]
    pub fn persistence(mut self, persistence: ZincPersistence) -> Self {
        self.persistence = Some(persistence);
        self
    }

    /// Build the `ZincWallet` instance.
    pub fn build(self) -> Result<ZincWallet, String> {
        let kind = self
            .kind
            .ok_or_else(|| "Wallet identity must be set".to_string())?;

        let mut scheme = self.scheme;
        if matches!(kind, WalletKind::WatchAddress(_)) {
            if scheme == AddressScheme::Dual {
                return Err("Address watch profiles support unified scheme only".to_string());
            }
            scheme = AddressScheme::Unified;
        }

        let (vault_ext, vault_int, payment_ext, payment_int) = kind.derive_descriptors(
            scheme,
            self.payment_address_type,
            self.network,
            self.account_index,
        );

        // 1. Vault (Taproot) wallet
        let (vault_wallet, loaded_vault_changeset) = if let Some(p) = &self.persistence {
            if let Some(changeset) = &p.taproot {
                let mut loader = Wallet::load()
                    .descriptor(KeychainKind::External, Some(vault_ext.clone()));
                
                if !matches!(kind, WalletKind::WatchAddress(_)) {
                    loader = loader.descriptor(KeychainKind::Internal, Some(vault_int.clone()));
                }

                let res = loader
                    .extract_keys()
                    .load_wallet_no_persist(changeset.clone());

                match res {
                    Ok(Some(w)) => (w, changeset.clone()),
                    Ok(None) | Err(_) => {
                        let creator = if matches!(kind, WalletKind::WatchAddress(_)) {
                            Wallet::create_single(vault_ext)
                        } else {
                            Wallet::create(vault_ext, vault_int)
                        };
                        let w = creator
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| format!("Failed to create taproot wallet: {e}"))?;
                        (w, bdk_wallet::ChangeSet::default())
                    }
                }
            } else {
                let creator = if matches!(kind, WalletKind::WatchAddress(_)) {
                    Wallet::create_single(vault_ext)
                } else {
                    Wallet::create(vault_ext, vault_int)
                };
                let w = creator
                    .network(self.network)
                    .create_wallet_no_persist()
                    .map_err(|e| format!("Failed to create taproot wallet: {e}"))?;
                (w, bdk_wallet::ChangeSet::default())
            }
        } else {
            let creator = if matches!(kind, WalletKind::WatchAddress(_)) {
                Wallet::create_single(vault_ext)
            } else {
                Wallet::create(vault_ext, vault_int)
            };
            let w = creator
                .network(self.network)
                .create_wallet_no_persist()
                .map_err(|e| format!("Failed to create taproot wallet: {e}"))?;
            (w, bdk_wallet::ChangeSet::default())
        };

        // 2. Payment wallet (optional, for dual-scheme)
        let (payment_wallet, loaded_payment_changeset) =
            if let (Some(pay_ext), Some(pay_int)) = (payment_ext, payment_int) {
                let (wallet, changeset) = if let Some(p) = &self.persistence {
                    if let Some(changeset) = &p.payment {
                        let res = Wallet::load()
                            .descriptor(KeychainKind::External, Some(pay_ext.clone()))
                            .descriptor(KeychainKind::Internal, Some(pay_int.clone()))
                            .extract_keys()
                            .load_wallet_no_persist(changeset.clone());

                        match res {
                            Ok(Some(w)) => (w, Some(changeset.clone())),
                            Ok(None) | Err(_) => {
                                let w = Wallet::create(pay_ext, pay_int)
                                    .network(self.network)
                                    .create_wallet_no_persist()
                                    .map_err(|e| format!("Failed to create payment wallet: {e}"))?;
                                (w, None)
                            }
                        }
                    } else {
                        let w = Wallet::create(pay_ext, pay_int)
                            .network(self.network)
                            .create_wallet_no_persist()
                            .map_err(|e| format!("Failed to create payment wallet: {e}"))?;
                        (w, None)
                    }
                } else {
                    let w = Wallet::create(pay_ext, pay_int)
                        .network(self.network)
                        .create_wallet_no_persist()
                        .map_err(|e| format!("Failed to create payment wallet: {e}"))?;
                    (w, None)
                };
                (Some(wallet), changeset)
            } else {
                (None, None)
            };

        Ok(ZincWallet {
            vault_wallet,
            payment_wallet,
            scheme: self.scheme,
            derivation_mode: self.derivation_mode,
            payment_address_type: self.payment_address_type,
            loaded_vault_changeset,
            loaded_payment_changeset,
            account_index: self.account_index,
            mode: self.mode,
            scan_policy: self.scan_policy,
            inscribed_utxos: std::collections::HashSet::default(),
            inscriptions: Vec::new(),
            rune_balances: Vec::new(),
            ordinals_verified: false,
            ordinals_metadata_complete: false,
            kind,
            is_syncing: false,
            account_generation: 0,
        })
    }

    /// Build a hardware wallet profile from public descriptors.
    pub fn build_hardware(
        self,
        fingerprint_hex: &str,
        taproot_external_desc: String,
        taproot_internal_desc: String,
        payment_external_desc: Option<String>,
        payment_internal_desc: Option<String>,
    ) -> Result<ZincWallet, String> {
        let fingerprint_vec = hex::decode(fingerprint_hex)
            .map_err(|e| format!("Invalid fingerprint hex: {e}"))?;
        let fingerprint: [u8; 4] = fingerprint_vec
            .try_into()
            .map_err(|_| "Fingerprint must be 4 bytes".to_string())?;

        let network = self.network;
        let account_index = self.account_index;
        let persistence = self.persistence;

        let scheme = if payment_external_desc.is_some() {
            AddressScheme::Dual
        } else {
            AddressScheme::Unified
        };

        // 1. Vault (Taproot) wallet from public descriptors
        let (vault_wallet, loaded_vault_changeset) = if let Some(p) = &persistence {
            if let Some(changeset) = &p.taproot {
                let res = Wallet::load()
                    .descriptor(KeychainKind::External, Some(taproot_external_desc.clone()))
                    .descriptor(KeychainKind::Internal, Some(taproot_internal_desc.clone()))
                    .extract_keys()
                    .load_wallet_no_persist(changeset.clone());

                match res {
                    Ok(Some(w)) => (w, changeset.clone()),
                    Ok(None) | Err(_) => {
                        let w = Wallet::create(taproot_external_desc.clone(), taproot_internal_desc.clone())
                            .network(network)
                            .create_wallet_no_persist()
                            .map_err(|e| format!("Failed to create taproot wallet from descriptor: {e}"))?;
                        (w, bdk_wallet::ChangeSet::default())
                    }
                }
            } else {
                let w = Wallet::create(taproot_external_desc.clone(), taproot_internal_desc.clone())
                    .network(network)
                    .create_wallet_no_persist()
                    .map_err(|e| format!("Failed to create taproot wallet from descriptor: {e}"))?;
                (w, bdk_wallet::ChangeSet::default())
            }
        } else {
            let w = Wallet::create(taproot_external_desc.clone(), taproot_internal_desc.clone())
                .network(network)
                .create_wallet_no_persist()
                .map_err(|e| format!("Failed to create taproot wallet from descriptor: {e}"))?;
            (w, bdk_wallet::ChangeSet::default())
        };

        // 2. Payment wallet (optional, for dual-scheme)
        let (payment_wallet, loaded_payment_changeset) =
            if let (Some(pay_ext), Some(pay_int)) = (&payment_external_desc, &payment_internal_desc) {
                let (wallet, changeset) = if let Some(p) = &persistence {
                    if let Some(changeset) = &p.payment {
                        let res = Wallet::load()
                            .descriptor(KeychainKind::External, Some(pay_ext.clone()))
                            .descriptor(KeychainKind::Internal, Some(pay_int.clone()))
                            .extract_keys()
                            .load_wallet_no_persist(changeset.clone());

                        match res {
                            Ok(Some(w)) => (w, Some(changeset.clone())),
                            Ok(None) | Err(_) => {
                                let w = Wallet::create(pay_ext.clone(), pay_int.clone())
                                    .network(network)
                                    .create_wallet_no_persist()
                                    .map_err(|e| format!("Failed to create payment wallet from descriptor: {e}"))?;
                                (w, None)
                            }
                        }
                    } else {
                        let w = Wallet::create(pay_ext.clone(), pay_int.clone())
                            .network(network)
                            .create_wallet_no_persist()
                            .map_err(|e| format!("Failed to create payment wallet from descriptor: {e}"))?;
                        (w, None)
                    }
                } else {
                    let w = Wallet::create(pay_ext.clone(), pay_int.clone())
                        .network(network)
                        .create_wallet_no_persist()
                        .map_err(|e| format!("Failed to create payment wallet from descriptor: {e}"))?;
                    (w, None)
                };
                (Some(wallet), changeset)
            } else {
                (None, None)
            };

        Ok(ZincWallet {
            vault_wallet,
            payment_wallet,
            scheme,
            derivation_mode: self.derivation_mode,
            payment_address_type: self.payment_address_type,
            loaded_vault_changeset,
            loaded_payment_changeset,
            account_index,
            mode: ProfileMode::Watch,
            scan_policy: self.scan_policy,
            inscribed_utxos: std::collections::HashSet::default(),
            inscriptions: Vec::new(),
            rune_balances: Vec::new(),
            ordinals_verified: false,
            ordinals_metadata_complete: false,
            kind: WalletKind::Hardware { 
                fingerprint,
                taproot_external: taproot_external_desc,
                payment_external: payment_external_desc,
            },
            is_syncing: false,
            account_generation: 0,
        })
    }
}

/// Serializable persistence snapshot for taproot/payment wallet changesets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZincPersistence {
    /// Merged changeset for the taproot wallet.
    pub taproot: Option<bdk_wallet::ChangeSet>,
    /// Merged changeset for the optional payment wallet.
    pub payment: Option<bdk_wallet::ChangeSet>,
}

fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_builder_basic() {
        use bdk_wallet::bitcoin::bip32::Xpriv;
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let master_xprv = Xpriv::new_master(Network::Signet, seed.as_ref()).expect("valid seed");
        
        let wallet = WalletBuilder::new(Network::Signet)
            .kind(WalletKind::Seed { master_xprv })
            .build()
            .unwrap();

        assert_eq!(wallet.vault_wallet.network(), Network::Signet);
        assert!(wallet.is_unified());
    }

    #[test]
    fn flexible_full_scan_request_uses_explicit_start_time() {
        use bdk_wallet::bitcoin::bip32::Xpriv;
        let mnemonic = ZincMnemonic::generate(12).unwrap();
        let seed = mnemonic.to_seed("");
        let master_xprv = Xpriv::new_master(Network::Signet, seed.as_ref()).expect("valid seed");
        let wallet = WalletBuilder::new(Network::Signet)
            .kind(WalletKind::Seed { master_xprv })
            .build()
            .unwrap();

        let explicit_start = 1_777_777_777_u64;
        let req = ZincWallet::flexible_full_scan_request(
            &wallet.vault_wallet,
            ScanPolicy::default(),
            explicit_start,
        );
        assert_eq!(req.start_time(), explicit_start);
    }
}
