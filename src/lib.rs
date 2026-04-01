//! Zinc Core - Bitcoin + Ordinals wallet engine.
//!
//! `zinc-core` provides reusable wallet primitives for native Rust and WASM hosts:
//! mnemonic handling, descriptor-backed account management, sync helpers, transaction
//! signing, and Ordinal Shield PSBT analysis.
//!
//! Quick start:
//! ```rust
//! use zinc_core::{Network, WalletBuilder, ZincMnemonic};
//!
//! let mnemonic = ZincMnemonic::parse(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//! )
//! .expect("valid mnemonic");
//! let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic)
//!     .build()
//!     .expect("wallet");
//! let _address = wallet.next_taproot_address().expect("address");
//! ```
//!
//! Additional examples are available in `examples/`:
//! `wallet_setup`, `sync_and_balance`, and `psbt_sign_audit`.

use serde::Serialize;
#[cfg(any(target_arch = "wasm32", test))]
use std::future::Future;
use wasm_bindgen::prelude::*;

#[macro_use]
mod logging;

// Core modules
pub mod builder;
pub mod crypto;
pub mod error;
/// Transaction history models and wallet history helpers.
pub mod history;
pub mod keys;
/// Offer envelope models and deterministic offer hashing/signature helpers.
pub mod offer;
/// Offer acceptance safety checks and signing plan derivation.
pub mod offer_accept;
/// Offer creation helpers for ord-compatible buyer offers.
pub mod offer_create;
/// Nostr event models and signing/verification helpers for decentralized offers.
pub mod offer_nostr;
/// Native Nostr relay publish/discovery transport for offer events.
#[cfg(not(target_arch = "wasm32"))]
pub mod offer_relay;
/// Ordinals data models, HTTP client, and protection analysis.
pub mod ordinals;
/// Signed pairing + sign-intent protocol primitives.
pub mod sign_intent;

// Re-exports for convenience
pub use builder::{
    Account, AddressScheme, CreatePsbtRequest, CreatePsbtTransportRequest, DiscoveryAccountPlan,
    DiscoveryContext, Seed64, SignOptions, SyncRequestType, SyncSleeper, WalletBuilder,
    ZincBalance, ZincPersistence, ZincSyncRequest, ZincWallet,
};
pub use error::{ZincError, ZincResult};
pub use history::TxItem;
pub use keys::{taproot_descriptors, DescriptorPair, ZincMnemonic};
pub use offer::OfferEnvelopeV1;
pub use offer_accept::{prepare_offer_acceptance, OfferAcceptancePlanV1};
pub use offer_create::{CreateOfferRequest, OfferCreateResultV1};
pub use offer_nostr::{NostrOfferEvent, OFFER_EVENT_KIND};
#[cfg(not(target_arch = "wasm32"))]
pub use offer_relay::{NostrRelayClient, RelayPublishResult, RelayQueryOptions};
pub use ordinals::client::OrdClient;
pub use ordinals::types::{Inscription, Satpoint};
pub use sign_intent::{
    build_signed_pairing_ack, build_signed_pairing_ack_with_granted,
    build_signed_pairing_complete_receipt, build_signed_sign_intent_rejection_receipt,
    decode_pairing_ack_envelope_event, decode_pairing_ack_envelope_event_with_secret,
    decode_signed_pairing_complete_receipt_event,
    decode_signed_pairing_complete_receipt_event_with_secret, decode_signed_sign_intent_event,
    decode_signed_sign_intent_event_with_secret, decode_signed_sign_intent_receipt_event,
    decode_signed_sign_intent_receipt_event_with_secret, decrypt_pairing_transport_content,
    encrypt_pairing_transport_content, generate_secret_key_hex, pairing_tag_hash_hex,
    pairing_transport_tags, pubkey_hex_from_secret_key, verify_pairing_approval,
    BuildBuyerOfferIntentV1, CapabilityPolicyV1, NostrTransportEventV1, PairingAckDecisionV1,
    PairingAckEnvelopeV1, PairingAckV1, PairingCompleteReceiptStatusV1, PairingCompleteReceiptV1,
    PairingLinkApprovalV1, PairingRequestV1, SignIntentActionV1, SignIntentPayloadV1,
    SignIntentReceiptStatusV1, SignIntentReceiptV1, SignIntentV1, SignSellerInputIntentV1,
    SignedPairingAckV1, SignedPairingCompleteReceiptV1, SignedPairingRequestV1,
    SignedSignIntentReceiptV1, SignedSignIntentV1, NOSTR_PAIRING_ACK_TYPE_TAG_VALUE,
    NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE, NOSTR_SIGN_INTENT_APP_TAG_VALUE,
    NOSTR_SIGN_INTENT_RECEIPT_TYPE_TAG_VALUE, NOSTR_SIGN_INTENT_TYPE_TAG_VALUE, NOSTR_TAG_APP_KEY,
    NOSTR_TAG_PAIRING_HASH_KEY, NOSTR_TAG_RECIPIENT_PUBKEY_KEY, NOSTR_TAG_TYPE_KEY,
    PAIRING_TRANSPORT_EVENT_KIND,
};

// Re-export bitcoin types we use
pub use bdk_wallet::bitcoin::Network;
use bdk_wallet::KeychainKind;

// ============================================================================
// Core Logic (Pure Rust)
// ============================================================================

#[doc(hidden)]
/// Mnemonic material returned by wallet generation/decryption helpers.
pub struct WalletResult {
    /// Full normalized BIP-39 mnemonic phrase.
    pub phrase: String,
    /// Phrase split into individual words.
    pub words: Vec<String>,
}

#[doc(hidden)]
/// Generate a new mnemonic-backed wallet result for native Rust callers.
pub fn generate_wallet_internal(word_count: u8) -> Result<WalletResult, ZincError> {
    let mnemonic = ZincMnemonic::generate(word_count)?;
    Ok(WalletResult {
        phrase: mnemonic.phrase(),
        words: mnemonic.words(),
    })
}

#[doc(hidden)]
/// Validate whether `phrase` is a syntactically valid BIP-39 mnemonic.
pub fn validate_mnemonic_internal(phrase: &str) -> bool {
    ZincMnemonic::parse(phrase).is_ok()
}

#[doc(hidden)]
/// Derive the first external Taproot address from a mnemonic on `network`.
pub fn derive_address_internal(phrase: &str, network: Network) -> Result<String, ZincError> {
    let mnemonic = ZincMnemonic::parse(phrase)?;
    let descriptors = crate::keys::taproot_descriptors(&mnemonic, network)?;

    let wallet = bdk_wallet::Wallet::create(
        descriptors.external.to_string(),
        descriptors.internal.to_string(),
    )
    .network(network)
    .create_wallet_no_persist()
    .map_err(|e| ZincError::BdkError(e.to_string()))?;

    let address = wallet.peek_address(KeychainKind::External, 0);
    Ok(address.address.to_string())
}

#[doc(hidden)]
/// Encrypt a mnemonic phrase with a password and return serialized JSON payload.
pub fn encrypt_wallet_internal(mnemonic: &str, password: &str) -> Result<String, ZincError> {
    let m = ZincMnemonic::parse(mnemonic)?;
    let encrypted = crypto::encrypt_seed(m.phrase().as_bytes(), password)?;
    serde_json::to_string(&encrypted).map_err(|e| ZincError::SerializationError(e.to_string()))
}

#[doc(hidden)]
/// Decrypt an encrypted wallet JSON payload and recover mnemonic details.
pub fn decrypt_wallet_internal(
    encrypted_json: &str,
    password: &str,
) -> Result<WalletResult, ZincError> {
    let encrypted: crypto::EncryptedWallet = serde_json::from_str(encrypted_json)
        .map_err(|e| ZincError::SerializationError(e.to_string()))?;

    let plaintext = crypto::decrypt_seed(&encrypted, password)?;

    let phrase = String::from_utf8(plaintext.to_vec())
        .map_err(|e| ZincError::SerializationError(format!("Invalid UTF-8: {}", e)))?;

    let mnemonic = ZincMnemonic::parse(&phrase)?;

    Ok(WalletResult {
        phrase: mnemonic.phrase(),
        words: mnemonic.words(),
    })
}

#[doc(hidden)]
/// Encrypt arbitrary UTF-8 secret material with a password and return serialized JSON payload.
pub fn encrypt_secret_internal(secret: &str, password: &str) -> Result<String, ZincError> {
    let encrypted = crypto::encrypt_seed(secret.as_bytes(), password)?;
    serde_json::to_string(&encrypted).map_err(|e| ZincError::SerializationError(e.to_string()))
}

#[doc(hidden)]
/// Decrypt an encrypted secret JSON payload and recover UTF-8 plaintext.
pub fn decrypt_secret_internal(encrypted_json: &str, password: &str) -> Result<String, ZincError> {
    let encrypted: crypto::EncryptedWallet = serde_json::from_str(encrypted_json)
        .map_err(|e| ZincError::SerializationError(e.to_string()))?;
    let plaintext = crypto::decrypt_seed(&encrypted, password)?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|e| ZincError::SerializationError(format!("Invalid UTF-8: {}", e)))
}

// ============================================================================
// WASM Bindings
// ============================================================================

use std::sync::Once;

static INIT: Once = Once::new();
const LOG_TARGET_WASM: &str = "zinc_core::wasm";

#[cfg(any(target_arch = "wasm32", test))]
async fn account_is_active_from_receive_scan<F, Fut>(
    address_scan_depth: u32,
    mut has_activity_at: F,
) -> bool
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = bool>,
{
    let depth = address_scan_depth.max(1);
    const ADDRESS_SCAN_BATCH_SIZE: u32 = 20;

    let mut batch_start = 0;
    while batch_start < depth {
        let batch_end = (batch_start + ADDRESS_SCAN_BATCH_SIZE).min(depth);
        let mut checks = Vec::with_capacity((batch_end - batch_start) as usize);
        for address_index in batch_start..batch_end {
            checks.push(has_activity_at(address_index));
        }

        let results = futures_util::future::join_all(checks).await;
        if results.into_iter().any(|is_active| is_active) {
            return true;
        }

        batch_start = batch_end;
    }

    false
}

/// Initialize WASM module (call once on load).
#[wasm_bindgen(start)]
pub fn init() {
    zinc_log_trace!(target: LOG_TARGET_WASM, "init invoked");
    INIT.call_once(|| {
        // Better panic messages in the console
        console_error_panic_hook::set_once();
        zinc_log_info!(target: LOG_TARGET_WASM, "WASM module initialized");
    });
}

/// Set runtime log level for zinc-core internals.
#[wasm_bindgen]
pub fn set_log_level(level: &str) -> Result<(), JsValue> {
    let Some(parsed) = logging::parse_level(level) else {
        zinc_log_warn!(
            target: LOG_TARGET_WASM,
            "rejected invalid log level request ({})",
            logging::redacted_field("requested_level", level)
        );
        zinc_log_error!(
            target: LOG_TARGET_WASM,
            "invalid runtime log level request rejected"
        );
        return Err(JsValue::from_str(
            "Invalid log level. Use one of: off, error, warn, info, debug, trace",
        ));
    };

    logging::set_log_level(parsed);
    zinc_log_info!(
        target: LOG_TARGET_WASM,
        "runtime log level updated to {}",
        parsed.as_str()
    );
    Ok(())
}

/// Enable or disable zinc-core logging at runtime.
#[wasm_bindgen]
pub fn set_logging_enabled(enabled: bool) {
    logging::set_logging_enabled(enabled);
    zinc_log_info!(
        target: LOG_TARGET_WASM,
        "runtime logging {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

/// Get current runtime log level.
#[wasm_bindgen]
pub fn get_log_level() -> String {
    logging::get_log_level().as_str().to_string()
}

/// Generate a new wallet with a random mnemonic.
#[wasm_bindgen]
pub fn generate_wallet(word_count: u8) -> Result<JsValue, JsValue> {
    let result =
        generate_wallet_internal(word_count).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let js_result = serde_json::json!({
        "words": result.words,
        "phrase": result.phrase,
    });

    serde_wasm_bindgen::to_value(&js_result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Validate a mnemonic phrase.
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> bool {
    validate_mnemonic_internal(phrase)
}

/// Derive a Taproot address from a mnemonic.
#[wasm_bindgen]
pub fn derive_address(phrase: &str, network: &str) -> Result<String, JsValue> {
    let network = match network {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => return Err(JsValue::from_str("Invalid network")),
    };

    derive_address_internal(phrase, network).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encrypt a mnemonic with a password.
#[wasm_bindgen]
pub fn encrypt_wallet(mnemonic: &str, password: &str) -> Result<String, JsValue> {
    encrypt_wallet_internal(mnemonic, password).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
/// WASM response payload for mnemonic decryption.
pub struct DecryptResponse {
    /// Whether decryption succeeded.
    pub success: bool,
    /// Decrypted BIP-39 phrase.
    pub phrase: String,
    /// Decrypted phrase split into words.
    pub words: Vec<String>,
}

/// Decrypt an encrypted wallet blob.
#[wasm_bindgen]
pub fn decrypt_wallet(encrypted_json: &str, password: &str) -> Result<JsValue, JsValue> {
    zinc_log_debug!(target: LOG_TARGET_WASM,
        "decrypt_wallet called. Encrypted length: {}, Password length: {}",
        encrypted_json.len(),
        password.len()
    );

    let result = match decrypt_wallet_internal(encrypted_json, password) {
        Ok(res) => {
            zinc_log_debug!(target: LOG_TARGET_WASM,
                "Internal decryption success. Phrase length: {}",
                res.phrase.len()
            );
            res
        }
        Err(e) => {
            zinc_log_debug!(target: LOG_TARGET_WASM, "Internal decryption failed: {:?}", e);
            return Err(JsValue::from_str(&e.to_string()));
        }
    };

    let response = DecryptResponse {
        success: true,
        phrase: result.phrase,
        words: result.words,
    };

    zinc_log_debug!(target: LOG_TARGET_WASM, "Serializing response...");
    match serde_wasm_bindgen::to_value(&response) {
        Ok(val) => {
            zinc_log_debug!(target: LOG_TARGET_WASM, "Serialization success.");
            Ok(val)
        }
        Err(e) => {
            zinc_log_debug!(target: LOG_TARGET_WASM, "Serialization failed: {:?}", e);
            Err(JsValue::from_str(&e.to_string()))
        }
    }
}

/// Validate and verify a signed pairing request payload.
///
/// Returns a compact JSON string:
/// `{ "ok": true, "pairingId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_signed_pairing_request_json(payload_json: &str) -> Result<String, JsValue> {
    let pairing_id = crate::sign_intent::validate_signed_pairing_request_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "pairingId": pairing_id
    })
    .to_string())
}

/// Validate and verify a signed pairing ack payload.
///
/// Returns:
/// `{ "ok": true, "ackId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_signed_pairing_ack_json(payload_json: &str) -> Result<String, JsValue> {
    let ack_id = crate::sign_intent::validate_signed_pairing_ack_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "ackId": ack_id
    })
    .to_string())
}

/// Validate and verify a pairing ack transport envelope payload.
///
/// Returns:
/// `{ "ok": true, "envelopeId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_pairing_ack_envelope_json(payload_json: &str) -> Result<String, JsValue> {
    let envelope_id = crate::sign_intent::validate_pairing_ack_envelope_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "envelopeId": envelope_id
    })
    .to_string())
}

/// Validate and verify a signed pairing-complete receipt payload.
///
/// Returns:
/// `{ "ok": true, "receiptId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_signed_pairing_complete_receipt_json(
    payload_json: &str,
) -> Result<String, JsValue> {
    let receipt_id =
        crate::sign_intent::validate_signed_pairing_complete_receipt_json(payload_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "receiptId": receipt_id
    })
    .to_string())
}

/// Validate and verify a signed Nostr transport event payload.
///
/// Returns:
/// `{ "ok": true, "eventId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_nostr_transport_event_json(payload_json: &str) -> Result<String, JsValue> {
    let event_id = crate::sign_intent::validate_nostr_transport_event_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "eventId": event_id
    })
    .to_string())
}

/// Validate and verify a signed sign-intent payload.
///
/// Returns:
/// `{ "ok": true, "intentId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_signed_sign_intent_json(payload_json: &str) -> Result<String, JsValue> {
    let intent_id = crate::sign_intent::validate_signed_sign_intent_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "intentId": intent_id
    })
    .to_string())
}

/// Validate and verify a signed sign-intent receipt payload.
///
/// Returns:
/// `{ "ok": true, "receiptId": "<hex>" }`
#[wasm_bindgen]
pub fn validate_signed_sign_intent_receipt_json(payload_json: &str) -> Result<String, JsValue> {
    let receipt_id = crate::sign_intent::validate_signed_sign_intent_receipt_json(payload_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "receiptId": receipt_id
    })
    .to_string())
}

/// Verify a signed pairing request + signed pairing ack bundle at a given unix timestamp.
///
/// Returns:
/// `{ "ok": true, "approval": { ...PairingLinkApprovalV1 } }`
#[wasm_bindgen]
pub fn verify_pairing_approval_json(
    signed_request_json: &str,
    signed_ack_json: &str,
    now_unix: i64,
) -> Result<String, JsValue> {
    let approval = crate::sign_intent::verify_pairing_approval_json(
        signed_request_json,
        signed_ack_json,
        now_unix,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "approval": approval
    })
    .to_string())
}

// ============================================================================
// Stateful Wallet Interface
// ============================================================================

use std::cell::{Cell, RefCell};
use std::rc::Rc;

const VITALITY_MAGIC: u32 = 0x005a_11ad;
#[cfg(target_arch = "wasm32")]
const SYNC_STALE_ERROR: &str = "Wallet state changed during sync; stale result discarded";
#[cfg(target_arch = "wasm32")]
const ORD_SYNC_STALE_ERROR: &str =
    "Wallet state changed during ordinals sync; stale result discarded";

#[derive(Clone, Copy)]
struct WalletState {
    network: Network,
    scheme: AddressScheme,
    account_index: u32,
}

#[wasm_bindgen]
/// WASM-safe stateful wallet handle wrapping the core `ZincWallet`.
pub struct ZincWasmWallet {
    inner: Rc<RefCell<ZincWallet>>,
    phrase: String, // Stored for re-building inner wallet on scheme change
    state: Cell<WalletState>,
    vitality: u32,
}

#[wasm_bindgen]
impl ZincWasmWallet {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::needless_pass_by_value)]
    /// Create a wallet from a plaintext mnemonic phrase.
    ///
    /// `network` accepts: `mainnet`, `bitcoin`, `testnet`, `signet`, `regtest`.
    pub fn new(
        network: &str,
        phrase: &str,
        scheme_str: Option<String>,
        persistence_json: Option<String>,
        account_index: Option<u32>,
    ) -> Result<ZincWasmWallet, JsValue> {
        let network_enum = match network {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "signet" => Network::Signet,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return Err(JsValue::from_str("Invalid network")),
        };

        let mnemonic =
            ZincMnemonic::parse(phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Self::init_wallet(
            network_enum,
            phrase,
            mnemonic,
            scheme_str,
            persistence_json,
            account_index,
        )
    }

    /// Initialize wallet from encrypted wallet payload (preferred for security).
    #[wasm_bindgen]
    pub fn new_encrypted(
        network: &str,
        encrypted_json: &str,
        password: &str,
        scheme_str: Option<String>,
        persistence_json: Option<String>,
        account_index: Option<u32>,
    ) -> Result<ZincWasmWallet, JsValue> {
        let network_enum = match network {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "signet" => Network::Signet,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return Err(JsValue::from_str("Invalid network")),
        };

        let result = decrypt_wallet_internal(encrypted_json, password)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mnemonic =
            ZincMnemonic::parse(&result.phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Self::init_wallet(
            network_enum,
            &result.phrase,
            mnemonic,
            scheme_str,
            persistence_json,
            account_index,
        )
    }

    fn init_wallet(
        network: Network,
        phrase: &str,
        mnemonic: ZincMnemonic,
        scheme_str: Option<String>,
        persistence_json: Option<String>,
        account_index: Option<u32>,
    ) -> Result<ZincWasmWallet, JsValue> {
        // Default to Unified if not specified
        let scheme = match scheme_str.as_deref() {
            Some("dual") => AddressScheme::Dual,
            _ => AddressScheme::Unified,
        };

        let active_index = account_index.unwrap_or(0);

        let mut builder = WalletBuilder::from_mnemonic(network, &mnemonic);
        builder = builder.with_scheme(scheme).with_account_index(active_index);

        if let Some(json) = persistence_json {
            builder = builder
                .with_persistence(&json)
                .map_err(|e| JsValue::from_str(&e))?;
        }

        let wallet = builder.build().map_err(|e| JsValue::from_str(&e))?;

        Ok(ZincWasmWallet {
            inner: Rc::new(RefCell::new(wallet)),
            phrase: phrase.to_string(),
            state: Cell::new(WalletState {
                network,
                scheme,
                account_index: active_index,
            }),
            vitality: VITALITY_MAGIC,
        })
    }

    fn check_vitality(&self) -> Result<(), JsValue> {
        if self.vitality != VITALITY_MAGIC {
            return Err(JsValue::from_str("Wallet handle is stale or corrupted due to context destruction. Please reload the extension."));
        }
        // Defensive check: ensure the Rc's strong count is sane.
        // A count of 0 would trigger UB in Rc::clone / try_borrow.
        let sc = Rc::strong_count(&self.inner);
        if sc == 0 {
            return Err(JsValue::from_str(
                "Internal error: Rc strong count is 0 (memory corruption). Please reload the extension."
            ));
        }
        Ok(())
    }

    fn state_snapshot(&self) -> WalletState {
        self.state.get()
    }

    fn replace_wallet(
        &self,
        mut next_wallet: ZincWallet,
        next_state: WalletState,
        busy_context: &str,
    ) -> Result<(), JsValue> {
        match self.inner.try_borrow_mut() {
            Ok(mut inner) => {
                next_wallet.account_generation = inner.account_generation().wrapping_add(1);
                *inner = next_wallet;
                self.state.set(next_state);
                Ok(())
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy ({}): {}",
                busy_context, e
            ))),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn generation_mismatch_error(
        inner_rc: &Rc<RefCell<ZincWallet>>,
        expected_generation: u64,
        message: &str,
    ) -> Option<JsValue> {
        match inner_rc.try_borrow() {
            Ok(inner) if inner.account_generation() != expected_generation => {
                Some(JsValue::from_str(message))
            }
            _ => None,
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn clear_syncing_if_generation_matches(
        inner_rc: &Rc<RefCell<ZincWallet>>,
        expected_generation: u64,
    ) {
        if let Ok(mut inner) = inner_rc.try_borrow_mut() {
            if inner.account_generation() == expected_generation {
                inner.is_syncing = false;
            }
        }
    }

    /// Export current in-memory wallet changesets as serialized JSON.
    pub fn export_changeset(&self) -> Result<String, JsValue> {
        self.check_vitality()?;
        zinc_log_debug!(target: LOG_TARGET_WASM, "export_changeset called (wrapper)");
        let res = match self.inner.try_borrow() {
            Ok(inner) => inner
                .export_changeset()
                .map_err(|e| JsValue::from_str(&e))
                .and_then(|p| {
                    serde_json::to_string(&p).map_err(|e| JsValue::from_str(&e.to_string()))
                }),
            Err(e) => {
                zinc_log_debug!(target: LOG_TARGET_WASM, "export_changeset failed to borrow: {:?}", e);
                Err(JsValue::from_str(&format!(
                    "Wallet busy (export_changeset): {}",
                    e
                )))
            }
        };
        zinc_log_debug!(target: LOG_TARGET_WASM, "export_changeset finished (wrapper)");
        res
    }

    /// Change the address scheme (Unified <-> Dual) on the fly.
    /// This rebuilds the internal wallet using the stored phrase.
    pub fn set_scheme(&self, scheme_str: &str) -> Result<(), JsValue> {
        self.check_vitality()?;
        let new_scheme = match scheme_str {
            "dual" => AddressScheme::Dual,
            "unified" => AddressScheme::Unified,
            _ => return Err(JsValue::from_str("Invalid scheme")),
        };

        let state = self.state_snapshot();
        if state.scheme == new_scheme {
            return Ok(());
        }

        let mnemonic =
            ZincMnemonic::parse(&self.phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut builder = WalletBuilder::from_mnemonic(state.network, &mnemonic);
        builder = builder
            .with_scheme(new_scheme)
            .with_account_index(state.account_index);

        let next_wallet = builder.build().map_err(|e| JsValue::from_str(&e))?;
        self.replace_wallet(
            next_wallet,
            WalletState {
                scheme: new_scheme,
                ..state
            },
            "set_scheme",
        )
    }

    /// Switch the active account index.
    /// This rebuilds the internal wallet logic for the new account.
    /// Note: Persistence is NOT carried over automatically for clear separation.
    pub fn set_active_account(&self, account_index: u32) -> Result<(), JsValue> {
        self.check_vitality()?;
        let state = self.state_snapshot();
        if state.account_index == account_index {
            return Ok(());
        }

        let mnemonic =
            ZincMnemonic::parse(&self.phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut builder = WalletBuilder::from_mnemonic(state.network, &mnemonic);
        builder = builder
            .with_scheme(state.scheme)
            .with_account_index(account_index);

        let next_wallet = builder.build().map_err(|e| JsValue::from_str(&e))?;
        self.replace_wallet(
            next_wallet,
            WalletState {
                account_index,
                ..state
            },
            "set_active_account",
        )
    }

    /// Change the network on the fly.
    pub fn set_network(&self, network_str: &str) -> Result<(), JsValue> {
        self.check_vitality()?;
        let new_network = match network_str {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => return Err(JsValue::from_str("Invalid network")),
        };

        let state = self.state_snapshot();
        if state.network == new_network {
            return Ok(());
        }

        let mnemonic =
            ZincMnemonic::parse(&self.phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut builder = WalletBuilder::from_mnemonic(new_network, &mnemonic);
        builder = builder
            .with_scheme(state.scheme)
            .with_account_index(state.account_index);

        let next_wallet = builder.build().map_err(|e| JsValue::from_str(&e))?;
        self.replace_wallet(
            next_wallet,
            WalletState {
                network: new_network,
                ..state
            },
            "set_network",
        )
    }

    #[wasm_bindgen(js_name = get_accounts)]
    /// Enumerate account previews from index `0..count` for the active seed.
    pub fn get_accounts(&self, count: u32) -> Result<JsValue, JsValue> {
        self.check_vitality()?;

        // Optimize: parse mnemonic and derive seed only once
        let mnemonic = crate::keys::ZincMnemonic::parse(&self.phrase)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let state = self.state_snapshot();
        let network = state.network;
        let scheme = state.scheme;

        let mut accounts = Vec::new();
        for i in 0..count {
            let mut builder = WalletBuilder::from_mnemonic(network, &mnemonic);
            builder = builder.with_scheme(scheme).with_account_index(i);

            // Build temporary wallet (no persistence)
            let zwallet = builder.build().map_err(|e| JsValue::from_str(&e))?;

            // Use peek_address for speed (no revealing/saving in memory)
            let vault_addr = zwallet
                .vault_wallet
                .peek_address(KeychainKind::External, 0)
                .address;

            let vault_pubkey = zwallet
                .get_taproot_public_key(0)
                .unwrap_or_else(|_| "".to_string());

            let (payment_addr, payment_pubkey) = if scheme == AddressScheme::Dual {
                (
                    Some(
                        zwallet
                            .payment_wallet
                            .as_ref()
                            .ok_or_else(|| {
                                JsValue::from_str("Payment wallet missing in dual mode")
                            })?
                            .peek_address(KeychainKind::External, 0)
                            .address
                            .to_string(),
                    ),
                    Some(
                        zwallet
                            .get_payment_public_key(0)
                            .unwrap_or_else(|_| "".to_string()),
                    ),
                )
            } else {
                (None, None)
            };

            accounts.push(serde_json::json!({
                "index": i,
                "label": format!("Account {}", i),
                "taprootAddress": vault_addr.to_string(),
                "taprootPublicKey": vault_pubkey,
                "paymentAddress": payment_addr,
                "paymentPublicKey": payment_pubkey,
                // Backward-compatible aliases for older clients.
                "vaultAddress": vault_addr.to_string(),
                "vaultPublicKey": vault_pubkey,
            }));
        }

        serde_wasm_bindgen::to_value(&accounts).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return cached inscription list currently loaded in wallet state.
    pub fn get_inscriptions(&self) -> Result<JsValue, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => serde_wasm_bindgen::to_value(&inner.inscriptions).map_err(|e| {
                JsValue::from_str(&format!("Failed to serialize inscriptions: {}", e))
            }),
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (get_inscriptions): {}",
                e
            ))),
        }
    }

    /// Return total, spendable, display-spendable, and inscribed balances.
    pub fn get_balance(&self) -> Result<JsValue, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let balance = inner.get_balance();
                let json = serde_json::json!({
                    "total": {
                        "confirmed": balance.total.confirmed.to_sat(),
                        "trusted_pending": balance.total.trusted_pending.to_sat(),
                        "untrusted_pending": balance.total.untrusted_pending.to_sat(),
                        "immature": balance.total.immature.to_sat(),
                    },
                    "spendable": {
                        "confirmed": balance.spendable.confirmed.to_sat(),
                        "trusted_pending": balance.spendable.trusted_pending.to_sat(),
                        "untrusted_pending": balance.spendable.untrusted_pending.to_sat(),
                        "immature": balance.spendable.immature.to_sat(),
                    },
                    "display_spendable": {
                        "confirmed": balance.display_spendable.confirmed.to_sat(),
                        "trusted_pending": balance.display_spendable.trusted_pending.to_sat(),
                        "untrusted_pending": balance.display_spendable.untrusted_pending.to_sat(),
                        "immature": balance.display_spendable.immature.to_sat(),
                    },
                    "inscribed": balance.inscribed
                });

                // Use explicit serializer to ensure maps are converted to JS objects, not Map class
                let serializer =
                    serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
                json.serialize(&serializer)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (get_balance): {}",
                e
            ))),
        }
    }

    /// Return recent wallet transactions ordered by pending-first then newest-first.
    pub fn get_transactions(&self, limit: usize) -> Result<JsValue, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let txs = inner.get_transactions(limit);
                serde_wasm_bindgen::to_value(&txs)
                    .map_err(|e| JsValue::from(format!("Failed to serialize transactions: {e}")))
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (get_transactions): {}",
                e
            ))),
        }
    }

    /// Return first receive addresses/public keys for taproot/payment roles.
    ///
    /// In unified mode, `payment*` mirrors the same taproot branch.
    pub fn get_addresses(&self) -> Result<JsValue, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let account_idx = inner.account_index;
                let vault_addr = inner
                    .vault_wallet
                    .peek_address(KeychainKind::External, 0)
                    .address;
                let vault_pubkey = inner
                    .get_taproot_public_key(0)
                    .unwrap_or_else(|_| "".to_string());

                zinc_log_debug!(
                    target: LOG_TARGET_WASM,
                    "get_addresses - account: {}, taproot: {}",
                    account_idx,
                    vault_addr
                );

                // We use inner.is_unified() so address behavior follows active inner wallet state.
                let (payment_addr, payment_pubkey) = if inner.is_unified() {
                    (Some(vault_addr.to_string()), Some(vault_pubkey.clone()))
                } else {
                    let addr = inner
                        .payment_wallet
                        .as_ref()
                        .ok_or_else(|| JsValue::from_str("Payment wallet missing in dual mode"))?
                        .peek_address(KeychainKind::External, 0)
                        .address;
                    let pubkey = inner
                        .get_payment_public_key(0)
                        .unwrap_or_else(|_| "".to_string());
                    zinc_log_debug!(target: LOG_TARGET_WASM, "get_addresses - payment: {}", addr);
                    (Some(addr.to_string()), Some(pubkey))
                };

                let json = serde_json::json!({
                    "account_index": account_idx,
                    "taproot": vault_addr.to_string(),
                    "taprootPublicKey": vault_pubkey,
                    "payment": payment_addr,
                    "paymentPublicKey": payment_pubkey,
                    // Backward-compatible aliases for older clients.
                    "vault": vault_addr.to_string(),
                    "vaultPublicKey": vault_pubkey
                });
                serde_wasm_bindgen::to_value(&json).map_err(|e| JsValue::from(e.to_string()))
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (get_addresses): {}",
                e
            ))),
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = sync)]
    pub fn sync(&self, esplora_url: String) -> Result<js_sys::Promise, JsValue> {
        self.check_vitality()?;
        use crate::builder::{SyncRequestType, SyncSleeper};
        use bdk_esplora::EsploraAsyncExt;

        let inner_rc = self.inner.clone();

        Ok(wasm_bindgen_futures::future_to_promise(async move {
            zinc_log_debug!(
                target: LOG_TARGET_WASM,
                "sync start ({})",
                logging::redacted_field("esplora_url", &esplora_url)
            );

            // 1. Prepare Request (lock briefly)
            let (sync_req, sync_generation) = {
                match inner_rc.try_borrow_mut() {
                    Ok(mut inner) => {
                        if inner.is_syncing {
                            zinc_log_debug!(target: LOG_TARGET_WASM, "Sync already in progress, skipping.");
                            return Err(JsValue::from_str("Wallet Busy: Sync already in progress"));
                        }
                        inner.is_syncing = true;
                        zinc_log_debug!(target: LOG_TARGET_WASM, "borrow successful, preparing requests");
                        (inner.prepare_requests(), inner.account_generation())
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync: FAILED TO BORROW INNER: {:?}", e);
                        return Err(JsValue::from_str(&format!(
                            "Failed to borrow wallet inner state: {}",
                            e
                        )));
                    }
                }
            };

            let client = match esplora_client::Builder::new(&esplora_url)
                .build_async_with_sleeper::<SyncSleeper>()
            {
                Ok(c) => c,
                Err(e) => {
                    zinc_log_error!(target: LOG_TARGET_WASM, "failed to create esplora client");
                    zinc_log_debug!(
                        target: LOG_TARGET_WASM,
                        "failed to create esplora client: {:?}",
                        e
                    );
                    ZincWasmWallet::clear_syncing_if_generation_matches(&inner_rc, sync_generation);
                    if let Some(stale) = ZincWasmWallet::generation_mismatch_error(
                        &inner_rc,
                        sync_generation,
                        SYNC_STALE_ERROR,
                    ) {
                        return Err(stale);
                    }
                    return Err(JsValue::from(format!("{:?}", e)));
                }
            };

            // 2. Fetch (NO LOCK HELD)
            let vault_update_res: Result<bdk_wallet::Update, JsValue> = match sync_req.taproot {
                SyncRequestType::Full(req) => {
                    zinc_log_info!(target: LOG_TARGET_WASM, "starting taproot full scan");
                    client
                        .full_scan(req, 20, 1)
                        .await
                        .map(|u| u.into())
                        .map_err(|e| {
                            zinc_log_debug!(target: LOG_TARGET_WASM, "Vault full scan failed: {:?}", e);
                            JsValue::from(e.to_string())
                        })
                }
                SyncRequestType::Incremental(req) => {
                    zinc_log_info!(target: LOG_TARGET_WASM, "starting taproot incremental sync");
                    client.sync(req, 1).await.map(|u| u.into()).map_err(|e| {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "Vault sync failed: {:?}", e);
                        JsValue::from(e.to_string())
                    })
                }
            };

            let vault_update = match vault_update_res {
                Ok(u) => u,
                Err(e) => {
                    ZincWasmWallet::clear_syncing_if_generation_matches(&inner_rc, sync_generation);
                    if let Some(stale) = ZincWasmWallet::generation_mismatch_error(
                        &inner_rc,
                        sync_generation,
                        SYNC_STALE_ERROR,
                    ) {
                        return Err(stale);
                    }
                    return Err(e);
                }
            };

            let payment_update: Option<bdk_wallet::Update> = if let Some(req_type) =
                sync_req.payment
            {
                let update_res: Result<bdk_wallet::Update, JsValue> = match req_type {
                    SyncRequestType::Full(req) => {
                        zinc_log_info!(target: LOG_TARGET_WASM, "starting payment full scan");
                        client
                                .full_scan(req, 20, 1)
                                .await
                                .map(|u| u.into())
                                .map_err(|e| {
                                    zinc_log_debug!(target: LOG_TARGET_WASM, "Payment full scan failed: {:?}", e);
                                    JsValue::from(e.to_string())
                                })
                    }
                    SyncRequestType::Incremental(req) => {
                        zinc_log_info!(
                            target: LOG_TARGET_WASM,
                            "starting payment incremental sync"
                        );
                        client.sync(req, 1).await.map(|u| u.into()).map_err(|e| {
                                zinc_log_debug!(target: LOG_TARGET_WASM, "Payment sync failed: {:?}", e);
                                JsValue::from(e.to_string())
                            })
                    }
                };

                match update_res {
                    Ok(u) => Some(u),
                    Err(e) => {
                        ZincWasmWallet::clear_syncing_if_generation_matches(
                            &inner_rc,
                            sync_generation,
                        );
                        if let Some(stale) = ZincWasmWallet::generation_mismatch_error(
                            &inner_rc,
                            sync_generation,
                            SYNC_STALE_ERROR,
                        ) {
                            return Err(stale);
                        }
                        return Err(e);
                    }
                }
            } else {
                None
            };
            zinc_log_debug!(target: LOG_TARGET_WASM, "sync: chain client returned");

            // 3. Apply (lock briefly)
            let events = {
                match inner_rc.try_borrow_mut() {
                    Ok(mut inner) => {
                        if inner.account_generation() != sync_generation {
                            return Err(JsValue::from_str(SYNC_STALE_ERROR));
                        }
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync: applying updates");
                        let res = inner
                            .apply_sync(vault_update, payment_update)
                            .map_err(|e| {
                                inner.is_syncing = false;
                                zinc_log_error!(target: LOG_TARGET_WASM, "failed to apply sync");
                                zinc_log_debug!(
                                    target: LOG_TARGET_WASM,
                                    "failed to apply sync update: {}",
                                    e
                                );
                                JsValue::from(e)
                            })?;
                        inner.is_syncing = false;
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync: updates applied");
                        res
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "FAILED TO BORROW MUT INNER: {:?}", e);
                        return Err(JsValue::from_str(&format!(
                            "Failed to borrow wallet inner state (mut): {}",
                            e
                        )));
                    }
                }
            };
            zinc_log_debug!(target: LOG_TARGET_WASM, "sync: finished. events: {:?}", events);

            serde_wasm_bindgen::to_value(&events).map_err(|e| JsValue::from(e.to_string()))
        }))
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = discoverAccounts)]
    pub fn discover_accounts(
        &self,
        esplora_url: String,
        account_gap_limit: u32,
        address_scan_depth: Option<u32>,
        timeout_ms: Option<u32>,
    ) -> Result<js_sys::Promise, JsValue> {
        self.check_vitality()?;

        let mnemonic = crate::keys::ZincMnemonic::parse(&self.phrase)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let seed = crate::builder::Seed64::from_array(*mnemonic.to_seed(""));
        let state = self.state_snapshot();
        let network = state.network;
        let scheme = state.scheme;
        let account_gap_limit = account_gap_limit.max(1);
        let requested_address_scan_depth = address_scan_depth.unwrap_or(20).max(1);
        // Strict scan policy: account discovery checks only main receive addresses (external/0).
        let address_scan_depth = 1;
        let timeout_ms = timeout_ms.unwrap_or(120_000).max(1);

        Ok(wasm_bindgen_futures::future_to_promise(async move {
            zinc_log_debug!(
                target: LOG_TARGET_WASM,
                "discover_accounts start ({}, account_gap_limit={}, requested_scan_depth={}, effective_scan_depth={}, timeout_ms={})",
                logging::redacted_field("esplora_url", &esplora_url),
                account_gap_limit,
                requested_address_scan_depth,
                address_scan_depth,
                timeout_ms
            );

            let client = reqwest::Client::new();
            let mut max_active_index: i32 = -1;
            let mut current_gap = 0;
            let mut account_index: u32 = 0;
            let start_ms = js_sys::Date::now();
            let deadline_ms = start_ms + f64::from(timeout_ms);

            loop {
                if js_sys::Date::now() >= deadline_ms {
                    zinc_log_warn!(
                        target: LOG_TARGET_WASM,
                        "discover_accounts reached timeout budget after {}ms (best_so_far_max_active={})",
                        timeout_ms,
                        max_active_index
                    );
                    break;
                }

                if current_gap >= account_gap_limit {
                    break;
                }

                let mut builder = WalletBuilder::from_seed(network, seed);
                builder = builder
                    .with_scheme(scheme)
                    .with_account_index(account_index);

                let zwallet = builder.build().map_err(|e| JsValue::from_str(&e))?;
                let timed_out = std::cell::Cell::new(false);
                const ADDRESS_REQUEST_TIMEOUT_MS: u32 = 2_000;

                let check_activity = |addr_str: String| {
                    let client = client.clone();
                    let url = format!("{}/address/{}", esplora_url, addr_str);
                    async move {
                        let request = async {
                            if let Ok(resp) = client.get(&url).send().await {
                                if let Ok(json) = resp.json::<serde_json::Value>().await {
                                    let chain_txs =
                                        json["chain_stats"]["tx_count"].as_u64().unwrap_or(0);
                                    let mempool_txs =
                                        json["mempool_stats"]["tx_count"].as_u64().unwrap_or(0);
                                    return chain_txs > 0 || mempool_txs > 0;
                                }
                            }
                            false
                        };
                        let timeout =
                            gloo_timers::future::TimeoutFuture::new(ADDRESS_REQUEST_TIMEOUT_MS);
                        futures_util::pin_mut!(request);
                        futures_util::pin_mut!(timeout);

                        match futures_util::future::select(request, timeout).await {
                            futures_util::future::Either::Left((value, _)) => value,
                            futures_util::future::Either::Right((_timed_out, _)) => false,
                        }
                    }
                };

                // Scan each account's receive chain deeply enough to catch funds parked
                // on later derived addresses during recovery.
                let has_activity =
                    account_is_active_from_receive_scan(address_scan_depth, |address_index| {
                        let vault_addr = zwallet
                            .vault_wallet
                            .peek_address(KeychainKind::External, address_index)
                            .address
                            .to_string();

                        let payment_addr = if scheme == AddressScheme::Dual {
                            zwallet.payment_wallet.as_ref().map(|wallet| {
                                wallet
                                    .peek_address(KeychainKind::External, address_index)
                                    .address
                                    .to_string()
                            })
                        } else {
                            None
                        };

                        async {
                            if js_sys::Date::now() >= deadline_ms {
                                timed_out.set(true);
                                return false;
                            }
                            if check_activity(vault_addr).await {
                                return true;
                            }
                            if let Some(payment_addr) = payment_addr {
                                return check_activity(payment_addr).await;
                            }
                            false
                        }
                    })
                    .await;

                if timed_out.get() {
                    zinc_log_warn!(
                        target: LOG_TARGET_WASM,
                        "discover_accounts stopped mid-account scan due to timeout budget (account_index={})",
                        account_index
                    );
                    break;
                }

                if has_activity {
                    max_active_index = account_index as i32;
                    current_gap = 0;
                } else {
                    current_gap += 1;
                }

                account_index += 1;
            }

            let discovered_count = (max_active_index + 1) as u32;
            let final_count = if discovered_count > 0 {
                discovered_count
            } else {
                1
            }; // Always show at least 1 (also on timeout)

            zinc_log_debug!(target: LOG_TARGET_WASM,
                "discover_accounts finished. Found max active = {}, returning discovery count {}",
                max_active_index,
                final_count
            );

            Ok(JsValue::from(final_count))
        }))
    }

    #[wasm_bindgen(js_name = loadInscriptions)]
    /// Replace wallet inscription cache from a JS value of `Inscription[]`.
    ///
    /// Security: this is treated as unverified metadata cache only. Call
    /// `syncOrdinals` before spend flows that require verified protection state.
    pub fn load_inscriptions(&self, val: JsValue) -> Result<u32, JsValue> {
        self.check_vitality()?;
        zinc_log_debug!(target: LOG_TARGET_WASM, "load_inscriptions called with JsValue");

        let inscriptions: Vec<crate::ordinals::types::Inscription> =
            serde_wasm_bindgen::from_value(val).map_err(|e| {
                JsValue::from_str(&format!("Failed to parse inscriptions from JsValue: {}", e))
            })?;

        zinc_log_debug!(target: LOG_TARGET_WASM,
            "Parsed {} inscriptions from JsValue. Updating wallet state...",
            inscriptions.len()
        );

        match self.inner.try_borrow_mut() {
            Ok(mut inner) => {
                let count = inner.apply_unverified_inscriptions_cache(inscriptions);
                zinc_log_debug!(target: LOG_TARGET_WASM, "Inscriptions applied. New count: {}", count);
                Ok(count as u32)
            }
            Err(e) => {
                zinc_log_debug!(target: LOG_TARGET_WASM, "load_inscriptions FAILED to borrow mutable: {}", e);
                Err(JsValue::from_str(&format!(
                    "Wallet busy (load_inscriptions): {}",
                    e
                )))
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = syncOrdinals)]
    pub fn sync_ordinals(&self, ord_url: String) -> Result<js_sys::Promise, JsValue> {
        self.check_vitality()?;
        let inner_rc = self.inner.clone();

        Ok(wasm_bindgen_futures::future_to_promise(async move {
            zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals start");
            // 1. Collect info needed for sync (Borrow Read)
            let (addresses, wallet_height, sync_generation) = {
                match inner_rc.try_borrow_mut() {
                    Ok(mut inner) => {
                        if inner.is_syncing {
                            zinc_log_debug!(target: LOG_TARGET_WASM, "Ord sync skipped: Wallet is busy syncing.");
                            return Err(JsValue::from_str(
                                "Wallet Busy: Operation already in progress",
                            ));
                        }
                        inner.is_syncing = true;
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: collecting active addresses...");
                        let addrs = inner.collect_active_addresses();
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: collected {} addresses", addrs.len());
                        for a in &addrs {
                            zinc_log_debug!(
                                target: LOG_TARGET_WASM,
                                "sync_ordinals address queued: {}",
                                a
                            );
                        }
                        let height = inner.vault_wallet.local_chain().tip().height();
                        (addrs, height, inner.account_generation())
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: FAILED TO BORROW INNER: {:?}", e);
                        return Err(JsValue::from_str(&format!("Failed to borrow: {}", e)));
                    }
                }
            };

            // 2. Perform Network IO (NO Borrow Held)
            let client = crate::ordinals::OrdClient::new(ord_url.to_string());

            // 2a. Check Lag
            let ord_height = match client.get_indexing_height().await {
                Ok(h) => h,
                Err(e) => {
                    zinc_log_debug!(target: LOG_TARGET_WASM, "Failed to get ord height: {:?}", e);
                    ZincWasmWallet::clear_syncing_if_generation_matches(&inner_rc, sync_generation);
                    if let Some(stale) = ZincWasmWallet::generation_mismatch_error(
                        &inner_rc,
                        sync_generation,
                        ORD_SYNC_STALE_ERROR,
                    ) {
                        return Err(stale);
                    }
                    return Err(JsValue::from_str(&e.to_string()));
                }
            };

            if ord_height < wallet_height.saturating_sub(1) {
                // We need to set verified=false safely
                zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: Ord lagging, setting verified=false");
                match inner_rc.try_borrow_mut() {
                    Ok(mut inner) => {
                        if inner.account_generation() != sync_generation {
                            return Err(JsValue::from_str(ORD_SYNC_STALE_ERROR));
                        }
                        inner.ordinals_verified = false;
                        inner.is_syncing = false;
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM,
                            "sync_ordinals: Failed to borrow mut for lag update: {}",
                            e
                        );
                    }
                }
                return Err(JsValue::from_str(&format!(
                    "Ord Indexer is lagging! Ord: {}, Wallet: {}. Safety lock engaged.",
                    ord_height, wallet_height
                )));
            }

            // 2b. Fetch artifact metadata
            zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: fetching inscriptions");
            let mut all_inscriptions = Vec::new();
            let mut protected_outpoints = std::collections::HashSet::new();
            for addr_str in addresses {
                match client.get_inscriptions(&addr_str).await {
                    Ok(list) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM,
                            "sync_ordinals: found {} inscriptions for {}",
                            list.len(),
                            addr_str
                        );
                        all_inscriptions.extend(list);
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "Failed to fetch inscriptions for {}: {}", addr_str, e);
                        ZincWasmWallet::clear_syncing_if_generation_matches(
                            &inner_rc,
                            sync_generation,
                        );
                        if let Some(stale) = ZincWasmWallet::generation_mismatch_error(
                            &inner_rc,
                            sync_generation,
                            ORD_SYNC_STALE_ERROR,
                        ) {
                            return Err(stale);
                        }
                        return Err(JsValue::from_str(&format!(
                            "Failed to fetch for {}: {}",
                            addr_str, e
                        )));
                    }
                }

                match client.get_protected_outpoints(&addr_str).await {
                    Ok(outpoints) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM,
                            "sync_ordinals: found {} protected outputs for {}",
                            outpoints.len(),
                            addr_str
                        );
                        protected_outpoints.extend(outpoints);
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM,
                            "Failed to fetch protected outputs for {}: {}",
                            addr_str,
                            e
                        );
                        match inner_rc.try_borrow_mut() {
                            Ok(mut inner) => {
                                if inner.account_generation() != sync_generation {
                                    return Err(JsValue::from_str(ORD_SYNC_STALE_ERROR));
                                }
                                inner.ordinals_verified = false;
                                inner.is_syncing = false;
                            }
                            Err(_) => {}
                        }
                        return Err(JsValue::from_str(&format!(
                            "Failed to fetch protected outputs for {}: {}",
                            addr_str, e
                        )));
                    }
                }
            }
            zinc_log_debug!(target: LOG_TARGET_WASM,
                "sync_ordinals: total inscriptions found: {}",
                all_inscriptions.len()
            );

            // 3. Apply Update (Borrow Mut)
            zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: applying update (borrow mut)");
            let count = {
                match inner_rc.try_borrow_mut() {
                    Ok(mut inner) => {
                        if inner.account_generation() != sync_generation {
                            return Err(JsValue::from_str(ORD_SYNC_STALE_ERROR));
                        }
                        let c = inner
                            .apply_verified_ordinals_update(all_inscriptions, protected_outpoints);
                        inner.is_syncing = false; // FINISHED
                        c
                    }
                    Err(e) => {
                        zinc_log_debug!(target: LOG_TARGET_WASM, "sync_ordinals: FAILED TO BORROW MUT: {:?}", e);
                        return Err(JsValue::from_str(&format!("Failed to borrow mut: {}", e)));
                    }
                }
            };

            Ok(JsValue::from(count as u32))
        }))
    }
    // ========================================================================
    // Send Flow
    // ========================================================================

    fn create_psbt_with_transport(
        &self,
        transport: crate::builder::CreatePsbtTransportRequest,
        busy_label: &str,
    ) -> Result<String, JsValue> {
        let request = crate::builder::CreatePsbtRequest::try_from(transport)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        match self.inner.try_borrow_mut() {
            Ok(mut inner) => inner
                .create_psbt_base64(&request)
                .map_err(|e| JsValue::from_str(&e.to_string())),
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy ({}): {}",
                busy_label, e
            ))),
        }
    }

    /// Create an unsigned PSBT for sending BTC from an object request.
    ///
    /// Request shape:
    /// - `recipient: string`
    /// - `amountSats: number`
    /// - `feeRateSatVb: number`
    #[wasm_bindgen(js_name = createPsbt)]
    pub fn create_psbt_request(&self, request: JsValue) -> Result<String, JsValue> {
        self.check_vitality()?;

        let transport: crate::builder::CreatePsbtTransportRequest =
            serde_wasm_bindgen::from_value(request)
                .map_err(|e| JsValue::from_str(&format!("Invalid request: {e}")))?;

        self.create_psbt_with_transport(transport, "createPsbt")
    }

    /// Create an unsigned PSBT for sending BTC from positional args.
    ///
    /// Deprecated migration wrapper for consumers that haven't moved to
    /// `createPsbt(request)` yet.
    #[doc(hidden)]
    pub fn create_psbt(
        &self,
        recipient: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        self.create_psbt_with_transport(
            crate::builder::CreatePsbtTransportRequest {
                recipient: recipient.to_string(),
                amount_sats,
                fee_rate_sat_vb,
            },
            "create_psbt",
        )
    }

    /// Sign a PSBT using the wallet's internal keys.
    /// Returns the signed PSBT as a base64-encoded string.
    #[wasm_bindgen(js_name = signPsbt)]
    pub fn sign_psbt(&self, psbt_base64: &str, options: JsValue) -> Result<String, JsValue> {
        self.check_vitality()?;

        let sign_opts: Option<crate::builder::SignOptions> =
            if options.is_null() || options.is_undefined() {
                None
            } else {
                match serde_wasm_bindgen::from_value(options) {
                    Ok(opts) => Some(opts),
                    Err(e) => return Err(JsValue::from_str(&format!("Invalid options: {}", e))),
                }
            };

        match self.inner.try_borrow_mut() {
            Ok(mut inner) => inner
                .sign_psbt(psbt_base64, sign_opts)
                .map_err(JsValue::from),
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (sign_psbt): {}",
                e
            ))),
        }
    }

    /// Analyzes a PSBT for Ordinal Shield protection.
    /// Returns a JSON string containing the AnalysisResult.
    #[wasm_bindgen(js_name = analyzePsbt)]
    pub fn analyze_psbt(&self, psbt_base64: &str) -> Result<String, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => inner.analyze_psbt(psbt_base64).map_err(JsValue::from),
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (analyze_psbt): {}",
                e
            ))),
        }
    }

    /// Audits a PSBT under the warn-only Ordinal Shield policy.
    /// Returns `Ok(())` when analysis succeeds, or an `Error` for malformed/unanalyzable payloads.
    #[wasm_bindgen(js_name = auditPsbt)]
    pub fn audit_psbt(&self, psbt_base64: &str, options: JsValue) -> Result<(), JsValue> {
        self.check_vitality()?;

        let sign_opts: Option<crate::builder::SignOptions> =
            if options.is_null() || options.is_undefined() {
                None
            } else {
                match serde_wasm_bindgen::from_value(options) {
                    Ok(opts) => Some(opts),
                    Err(e) => return Err(JsValue::from_str(&format!("Invalid options: {}", e))),
                }
            };

        use base64::Engine;
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_base64)
            .map_err(|e| JsValue::from_str(&format!("Invalid base64: {e}")))?;

        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid PSBT: {e}")))?;

        let inner = self
            .inner
            .try_borrow()
            .map_err(|e| JsValue::from_str(&format!("Wallet busy (audit_psbt): {}", e)))?;

        // 1. Build known_inscriptions map
        let mut known_inscriptions: std::collections::HashMap<
            (bitcoin::Txid, u32),
            Vec<(String, u64)>,
        > = std::collections::HashMap::new();
        for ins in &inner.inscriptions {
            known_inscriptions
                .entry((ins.satpoint.outpoint.txid, ins.satpoint.outpoint.vout))
                .or_default()
                .push((ins.id.clone(), ins.satpoint.offset));
        }

        // 2. Perform Audit
        let allowed_inputs = sign_opts.as_ref().and_then(|o| o.sign_inputs.as_deref());

        crate::ordinals::shield::audit_psbt(
            &psbt,
            &known_inscriptions,
            allowed_inputs,
            inner.vault_wallet.network(),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Sign a message using the private key corresponding to the address.
    /// Returns signature string (base64).
    pub fn sign_message(&self, address: &str, message: &str) -> Result<String, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => inner
                .sign_message(address, message)
                .map_err(|e| JsValue::from_str(&e)),
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (sign_message): {}",
                e
            ))),
        }
    }

    /// Build a signed pairing-ack JSON payload for a validated signed pairing request.
    ///
    /// Uses the active account's first taproot key (`m/86'/coin'/account'/0/0`) as signer.
    #[wasm_bindgen(js_name = build_signed_pairing_ack)]
    pub fn build_signed_pairing_ack(
        &self,
        signed_request_json: &str,
        now_unix: i64,
        ack_ttl_secs: u32,
        granted_capabilities_json: Option<String>,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let wallet_secret_key_hex = inner
                    .get_pairing_secret_key_hex()
                    .map_err(|e| JsValue::from_str(&e))?;
                let signed_request: crate::sign_intent::SignedPairingRequestV1 =
                    serde_json::from_str(signed_request_json).map_err(|e| {
                        JsValue::from_str(&format!("invalid signed pairing request json: {e}"))
                    })?;
                let granted_capabilities = match granted_capabilities_json {
                    Some(raw_json) => {
                        let policy: crate::sign_intent::CapabilityPolicyV1 =
                            serde_json::from_str(&raw_json).map_err(|e| {
                                JsValue::from_str(&format!(
                                    "invalid granted capabilities json: {e}"
                                ))
                            })?;
                        Some(policy)
                    }
                    None => None,
                };

                let signed_ack = crate::sign_intent::build_signed_pairing_ack_with_granted(
                    &signed_request,
                    &wallet_secret_key_hex,
                    now_unix,
                    i64::from(ack_ttl_secs),
                    granted_capabilities,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

                serde_json::to_string(&signed_ack)
                    .map_err(|e| JsValue::from_str(&format!("failed to serialize signed ack: {e}")))
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (build_signed_pairing_ack): {}",
                e
            ))),
        }
    }

    /// Return the current account pairing transport pubkey (x-only Schnorr).
    #[wasm_bindgen(js_name = get_pairing_pubkey_hex)]
    pub fn get_pairing_pubkey_hex(&self) -> Result<String, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let secret_hex = inner
                    .get_pairing_secret_key_hex()
                    .map_err(|e| JsValue::from_str(&e))?;
                crate::sign_intent::pubkey_hex_from_secret_key(&secret_hex)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (get_pairing_pubkey_hex): {}",
                e
            ))),
        }
    }

    /// Build and sign a rejected sign-intent receipt using the account pairing key.
    #[wasm_bindgen(js_name = build_signed_sign_intent_rejection_receipt_json)]
    pub fn build_signed_sign_intent_rejection_receipt_json(
        &self,
        signed_intent_json: &str,
        created_at_unix: i64,
        rejection_reason: &str,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        let signed_intent: crate::sign_intent::SignedSignIntentV1 =
            serde_json::from_str(signed_intent_json)
                .map_err(|e| JsValue::from_str(&format!("invalid signed sign intent json: {e}")))?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let secret_hex = inner
                    .get_pairing_secret_key_hex()
                    .map_err(|e| JsValue::from_str(&e))?;
                let signed_receipt =
                    crate::sign_intent::build_signed_sign_intent_rejection_receipt(
                        &signed_intent,
                        &secret_hex,
                        created_at_unix,
                        rejection_reason,
                    )
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                serde_json::to_string(&signed_receipt).map_err(|e| {
                    JsValue::from_str(&format!(
                        "failed to serialize signed sign intent receipt: {e}"
                    ))
                })
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (build_signed_sign_intent_rejection_receipt_json): {}",
                e
            ))),
        }
    }

    /// Build a pairing ack envelope JSON payload from a signed pairing ack JSON string.
    #[wasm_bindgen(js_name = build_pairing_ack_envelope_json)]
    pub fn build_pairing_ack_envelope_json(
        &self,
        signed_ack_json: &str,
        created_at_unix: i64,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        let signed_ack: crate::sign_intent::SignedPairingAckV1 =
            serde_json::from_str(signed_ack_json)
                .map_err(|e| JsValue::from_str(&format!("invalid signed pairing ack json: {e}")))?;
        let envelope = crate::sign_intent::PairingAckEnvelopeV1::new(signed_ack, created_at_unix)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&envelope).map_err(|e| {
            JsValue::from_str(&format!("failed to serialize pairing ack envelope: {e}"))
        })
    }

    /// Build and sign a generic Nostr transport event using the account pairing key.
    #[wasm_bindgen(js_name = build_pairing_transport_event_json)]
    pub fn build_pairing_transport_event_json(
        &self,
        content_json: &str,
        type_tag: &str,
        pairing_id: &str,
        recipient_pubkey_hex: &str,
        created_at_unix: u64,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        match self.inner.try_borrow() {
            Ok(inner) => {
                let secret_hex = inner
                    .get_pairing_secret_key_hex()
                    .map_err(|e| JsValue::from_str(&e))?;
                let tags = crate::sign_intent::pairing_transport_tags(
                    type_tag,
                    pairing_id,
                    recipient_pubkey_hex,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let encrypted_content = crate::sign_intent::encrypt_pairing_transport_content(
                    content_json,
                    &secret_hex,
                    recipient_pubkey_hex,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let event = crate::sign_intent::NostrTransportEventV1::new(
                    crate::sign_intent::PAIRING_TRANSPORT_EVENT_KIND,
                    tags,
                    encrypted_content,
                    created_at_unix,
                    &secret_hex,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
                serde_json::to_string(&event).map_err(|e| {
                    JsValue::from_str(&format!("failed to serialize pairing transport event: {e}"))
                })
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (build_pairing_transport_event_json): {}",
                e
            ))),
        }
    }

    /// Decode/decrypt pairing transport event content using the account pairing key.
    #[wasm_bindgen(js_name = decode_pairing_transport_event_content_json)]
    pub fn decode_pairing_transport_event_content_json(
        &self,
        event_json: &str,
    ) -> Result<String, JsValue> {
        self.check_vitality()?;
        let event: crate::sign_intent::NostrTransportEventV1 = serde_json::from_str(event_json)
            .map_err(|e| JsValue::from_str(&format!("invalid transport event json: {e}")))?;
        event
            .verify()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        match self.inner.try_borrow() {
            Ok(inner) => {
                let secret_hex = inner
                    .get_pairing_secret_key_hex()
                    .map_err(|e| JsValue::from_str(&e))?;

                match crate::sign_intent::decrypt_pairing_transport_content(
                    &event.content,
                    &secret_hex,
                    &event.pubkey,
                ) {
                    Ok(decrypted) => Ok(decrypted),
                    Err(_) => {
                        serde_json::from_str::<serde_json::Value>(&event.content).map_err(|_| {
                            JsValue::from_str(
                                "failed to decrypt transport event content and plaintext fallback is not valid json",
                            )
                        })?;
                        Ok(event.content)
                    }
                }
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Wallet busy (decode_pairing_transport_event_content_json): {}",
                e
            ))),
        }
    }

    /// Broadcast a signed PSBT to the network.
    /// Returns the transaction ID (txid) as a hex string.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = broadcast)]
    pub fn broadcast(
        &self,
        signed_psbt_base64: String,
        esplora_url: String,
    ) -> Result<js_sys::Promise, JsValue> {
        self.check_vitality()?;
        use crate::builder::SyncSleeper;

        Ok(wasm_bindgen_futures::future_to_promise(async move {
            // Decode PSBT - no borrow needed
            use base64::Engine;
            let psbt_bytes = base64::engine::general_purpose::STANDARD
                .decode(&signed_psbt_base64)
                .map_err(|e| JsValue::from_str(&format!("Invalid base64: {e}")))?;

            let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
                .map_err(|e| JsValue::from_str(&format!("Invalid PSBT: {e}")))?;

            // Extract the finalized transaction
            let tx = psbt
                .extract_tx()
                .map_err(|e| JsValue::from_str(&format!("Failed to extract tx: {e}")))?;

            // Broadcast via Esplora (no RefCell borrow needed)
            let client = esplora_client::Builder::new(&esplora_url)
                .build_async_with_sleeper::<SyncSleeper>()
                .map_err(|e| JsValue::from_str(&format!("Failed to create client: {e:?}")))?;

            client
                .broadcast(&tx)
                .await
                .map_err(|e| JsValue::from_str(&format!("Broadcast failed: {e}")))?;

            Ok(JsValue::from(tx.compute_txid().to_string()))
        }))
    }
}

// Integration tests under src/tests/.
#[cfg(test)]
pub mod tests;
