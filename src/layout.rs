//! Derivation-layout descriptions for multi-layout discovery.
//!
//! A [`LayoutSpec`] names how a provider arranges keys under a seed: which
//! purpose/script each branch uses and whether "account N" means BIP-level
//! account N ([`DerivationMode::Account`]) or address index N under account 0
//! ([`DerivationMode::Index`], the Xverse/Unisat style). The host owns the
//! catalog of provider quirks and all network probing; this module only
//! derives addresses deterministically so a scan can ask "would this seed
//! under this layout have used these addresses?".
//!
//! Everything here is pure and wasm-safe.

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::{KeychainKind, Wallet};
use serde::{Deserialize, Serialize};

use crate::builder::{DerivationMode, PaymentAddressType, Seed64};

/// Script kind of one derivation branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptKind {
    /// BIP-86 taproot (`tr(...)`).
    Tr,
    /// BIP-84 native segwit (`wpkh(...)`).
    Wpkh,
    /// BIP-49 nested segwit (`sh(wpkh(...))`).
    ShWpkh,
    /// BIP-44 legacy (`pkh(...)`).
    Pkh,
}

impl ScriptKind {
    pub(crate) fn descriptor(self, account_path: &str, chain: u32) -> String {
        match self {
            ScriptKind::Tr => format!("tr({account_path}/{chain}/*)"),
            ScriptKind::Wpkh => format!("wpkh({account_path}/{chain}/*)"),
            ScriptKind::ShWpkh => format!("sh(wpkh({account_path}/{chain}/*))"),
            ScriptKind::Pkh => format!("pkh({account_path}/{chain}/*)"),
        }
    }
}

/// One derivation branch: purpose level + script kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchSpec {
    /// BIP-43 purpose (86, 84, 49, 44 — hardened at derivation time).
    pub purpose: u32,
    /// Script kind the branch produces.
    pub script: ScriptKind,
}

/// A complete layout: the ordinals/taproot branch, an optional payment
/// branch (None = unified, everything on taproot), and the account mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutSpec {
    /// Ordinals branch — must be taproot.
    pub vault: BranchSpec,
    /// Payment branch; `None` means unified (payments on the taproot branch).
    pub payment: Option<BranchSpec>,
    /// How logical account numbers map to derivation (account vs index style).
    pub derivation_mode: DerivationMode,
}

impl LayoutSpec {
    /// The layout Zinc itself uses: BIP-86 ordinals + BIP-84 payments,
    /// account-style derivation.
    #[must_use]
    pub fn zinc_default() -> Self {
        Self {
            vault: BranchSpec {
                purpose: 86,
                script: ScriptKind::Tr,
            },
            payment: Some(BranchSpec {
                purpose: 84,
                script: ScriptKind::Wpkh,
            }),
            derivation_mode: DerivationMode::Account,
        }
    }

    /// Reject layouts the wallet cannot represent.
    pub fn validate(&self) -> Result<(), String> {
        if self.vault.script != ScriptKind::Tr {
            return Err("Layout ordinals branch must be taproot".to_string());
        }
        if let Some(payment) = &self.payment {
            if payment.script == ScriptKind::Tr {
                return Err(
                    "Layout payment branch cannot be taproot — use a unified layout instead"
                        .to_string(),
                );
            }
        }
        const MAX_HARDENED: u32 = 0x7FFF_FFFF;
        if self.vault.purpose > MAX_HARDENED
            || self.payment.is_some_and(|p| p.purpose > MAX_HARDENED)
        {
            return Err("Layout purpose is out of range".to_string());
        }
        Ok(())
    }

    /// The [`PaymentAddressType`] this layout's payment branch implies, or
    /// `None` for unified layouts.
    #[must_use]
    pub fn implied_payment_address_type(&self) -> Option<PaymentAddressType> {
        self.payment.map(|payment| match payment.script {
            ScriptKind::Wpkh | ScriptKind::Tr => PaymentAddressType::NativeSegwit,
            ScriptKind::ShWpkh => PaymentAddressType::NestedSegwit,
            ScriptKind::Pkh => PaymentAddressType::Legacy,
        })
    }

    /// Map a logical account number to (derivation account, address index) —
    /// identical to the wallet's own `logical_account_path`.
    #[must_use]
    pub fn account_and_index(&self, logical_account: u32) -> (u32, u32) {
        match self.derivation_mode {
            DerivationMode::Account => (logical_account, 0),
            DerivationMode::Index => (0, logical_account),
        }
    }
}

/// Addresses derived for one branch of a layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutAddresses {
    /// Ordinals-branch addresses, `count` of them from the branch start.
    pub vault: Vec<String>,
    /// Payment-branch addresses when the layout has a payment branch.
    pub payment: Option<Vec<String>>,
}

fn coin_type(network: Network) -> u32 {
    u32::from(network != Network::Bitcoin)
}

fn derive_branch(
    xprv: &Xpriv,
    network: Network,
    branch: BranchSpec,
    account: u32,
    chain: u32,
    start_index: u32,
    count: u32,
) -> Result<Vec<String>, String> {
    let coin = coin_type(network);
    let account_path = format!("{xprv}/{}'/{coin}'/{account}'", branch.purpose);
    let receive = branch.script.descriptor(&account_path, 0);
    let change = branch.script.descriptor(&account_path, 1);
    let wallet = Wallet::create(receive, change)
        .network(network)
        .create_wallet_no_persist()
        .map_err(|e| format!("Layout descriptor rejected: {e}"))?;
    let keychain = if chain == 0 {
        KeychainKind::External
    } else {
        KeychainKind::Internal
    };
    Ok((start_index..start_index.saturating_add(count))
        .map(|index| wallet.peek_address(keychain, index).address.to_string())
        .collect())
}

/// Derive `count` addresses per branch for `logical_account` under `layout`.
///
/// `chain` selects receive (0) or change (1). In Index mode the logical
/// account's own address index is where funds actually land — scans should
/// still walk `start_index..start_index+count` from 0 to see gap-limit usage
/// the same way the originating wallet would have.
pub fn derive_layout_addresses(
    network: Network,
    seed: &Seed64,
    layout: &LayoutSpec,
    logical_account: u32,
    chain: u32,
    start_index: u32,
    count: u32,
) -> Result<LayoutAddresses, String> {
    layout.validate()?;
    if chain > 1 {
        return Err("chain must be 0 (receive) or 1 (change)".to_string());
    }
    let xprv =
        Xpriv::new_master(network, seed.as_ref()).map_err(|e| format!("Invalid seed: {e}"))?;
    let (account, _address_index) = layout.account_and_index(logical_account);

    let vault = derive_branch(
        &xprv,
        network,
        layout.vault,
        account,
        chain,
        start_index,
        count,
    )?;
    let payment = match &layout.payment {
        Some(branch) => Some(derive_branch(
            &xprv,
            network,
            *branch,
            account,
            chain,
            start_index,
            count,
        )?),
        None => None,
    };
    Ok(LayoutAddresses { vault, payment })
}
