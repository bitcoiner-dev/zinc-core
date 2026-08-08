#![cfg(target_arch = "wasm32")]
//! JS-contract tests for the `#[wasm_bindgen]` surface (W1): crypto free functions,
//! constructors, data getters, and state setters. Run under Node via wasm-bindgen-test.
//!
//! These verify the *JS boundary* (return shapes, round-trips, error mapping); the underlying
//! Rust logic is covered by the native suites.

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use zinc_core::{
    decrypt_secret, decrypt_wallet, decrypt_wallet_with_key, derive_address, encrypt_secret,
    encrypt_wallet, encrypt_wallet_with_key, generate_vault_key, validate_mnemonic, ZincWasmWallet,
};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn to_json(js: JsValue) -> serde_json::Value {
    serde_wasm_bindgen::from_value(js).expect("JsValue should deserialize")
}

fn wallet() -> ZincWasmWallet {
    ZincWasmWallet::new(
        "regtest",
        PHRASE,
        Some("unified".to_string()),
        None,
        Some(0),
        None,
        None,
    )
    .expect("seed wallet")
}

// ---------------- crypto free functions ----------------

#[wasm_bindgen_test]
fn validate_mnemonic_accepts_valid_and_rejects_invalid() {
    assert!(validate_mnemonic(PHRASE));
    assert!(!validate_mnemonic(
        "totally not a valid mnemonic phrase at all"
    ));
}

#[wasm_bindgen_test]
fn derive_address_returns_regtest_taproot_and_rejects_bad_network() {
    let addr = derive_address(PHRASE, "regtest").expect("derive");
    assert!(
        addr.starts_with("bcrt1p"),
        "expected regtest taproot, got {addr}"
    );
    assert!(derive_address(PHRASE, "not-a-network").is_err());
}

#[wasm_bindgen_test]
fn encrypt_then_decrypt_wallet_round_trips_phrase() {
    let enc = encrypt_wallet(PHRASE, "pw-123").expect("encrypt");
    let dec = to_json(decrypt_wallet(&enc, "pw-123").expect("decrypt"));
    assert_eq!(dec["phrase"].as_str().expect("phrase"), PHRASE);
}

#[wasm_bindgen_test]
fn decrypt_wallet_with_wrong_password_errors() {
    let enc = encrypt_wallet(PHRASE, "pw-123").expect("encrypt");
    assert!(decrypt_wallet(&enc, "wrong-password").is_err());
}

#[wasm_bindgen_test]
fn generated_vault_key_crosses_the_wasm_boundary_as_a_javascript_string() {
    let key = generate_vault_key();
    assert_eq!(key.length(), 64);
    assert!(JsValue::from(key).is_string());
}

#[wasm_bindgen_test]
fn keystore_wallet_decryption_preserves_the_wasm_response_shape() {
    let key = JsValue::from(generate_vault_key())
        .as_string()
        .expect("vault key string");
    let encrypted = encrypt_wallet_with_key(PHRASE, &key).expect("encrypt keystore wallet");
    let decrypted =
        to_json(decrypt_wallet_with_key(&encrypted, &key).expect("decrypt keystore wallet"));
    assert_eq!(decrypted["success"].as_bool(), Some(true));
    assert_eq!(decrypted["phrase"].as_str(), Some(PHRASE));
    assert_eq!(
        decrypted["words"].as_array().map(std::vec::Vec::len),
        Some(12)
    );
}

#[wasm_bindgen_test]
fn encrypt_then_decrypt_secret_round_trips() {
    let enc = encrypt_secret("super-secret-value", "pw").expect("encrypt secret");
    let decrypted = decrypt_secret(&enc, "pw").expect("decrypt secret");
    assert_eq!(
        JsValue::from(decrypted).as_string().as_deref(),
        Some("super-secret-value")
    );
}

// ---------------- constructors ----------------

#[wasm_bindgen_test]
fn new_encrypted_builds_a_usable_wallet() {
    let enc = encrypt_wallet(PHRASE, "pw").expect("encrypt");
    let w = ZincWasmWallet::new_encrypted(
        "regtest",
        &enc,
        "pw",
        Some("unified".to_string()),
        None,
        Some(0),
        None,
        None,
    )
    .expect("new_encrypted");
    let accts = to_json(w.get_accounts(1).expect("accounts"));
    assert_eq!(accts.as_array().expect("accounts array").len(), 1);
    let first_pubkey = accts[0]["taprootPublicKey"]
        .as_str()
        .expect("pubkey")
        .to_string();
    assert_eq!(first_pubkey.len(), 64);

    // The decrypted result owner has already been dropped. Account rebuilding must continue to
    // work from the mnemonic allocation transferred into the zeroizing wallet material.
    w.set_active_account(1).expect("switch account");
    let second = to_json(w.get_addresses().expect("second account"));
    assert_eq!(second["account_index"].as_u64(), Some(1));
    assert_ne!(
        second["taprootPublicKey"].as_str().expect("pubkey"),
        first_pubkey
    );
}

#[wasm_bindgen_test]
fn new_encrypted_with_wrong_password_errors() {
    let enc = encrypt_wallet(PHRASE, "pw").expect("encrypt");
    assert!(ZincWasmWallet::new_encrypted(
        "regtest",
        &enc,
        "nope",
        Some("unified".to_string()),
        None,
        Some(0),
        None,
        None,
    )
    .is_err());
}

#[wasm_bindgen_test]
fn locking_a_wallet_invalidates_the_handle() {
    let mut wallet = wallet();
    assert!(wallet.get_pairing_pubkey_hex().is_ok());
    wallet
        .lock_private_material()
        .expect("lock private material");
    assert!(wallet.get_pairing_pubkey_hex().is_err());
    assert!(wallet.get_addresses().is_err());
}

#[wasm_bindgen_test]
fn new_watch_address_builds_wallet_for_its_address() {
    let addr = derive_address(PHRASE, "regtest").expect("derive");
    let w = ZincWasmWallet::new_watch_address("regtest", &addr, None, None).expect("watch wallet");
    let accts = to_json(w.get_accounts(1).expect("accounts"));
    assert_eq!(accts[0]["taprootAddress"].as_str().expect("addr"), addr);
}

#[wasm_bindgen_test]
fn new_watch_address_rejects_invalid_address() {
    assert!(ZincWasmWallet::new_watch_address("regtest", "not-an-address", None, None).is_err());
}

// ---------------- data getters (fresh wallet) ----------------

#[wasm_bindgen_test]
fn get_balance_is_object_with_zero_inscribed() {
    let bal = to_json(wallet().get_balance().expect("balance"));
    assert!(bal.is_object());
    assert_eq!(bal["inscribed"].as_u64(), Some(0));
}

#[wasm_bindgen_test]
fn get_utxos_is_empty_array_for_fresh_wallet() {
    let utxos = to_json(wallet().get_utxos().expect("utxos"));
    assert_eq!(utxos.as_array().expect("array").len(), 0);
}

#[wasm_bindgen_test]
fn get_transactions_is_empty_array_for_fresh_wallet() {
    let txs = to_json(wallet().get_transactions(50).expect("txs"));
    assert_eq!(txs.as_array().expect("array").len(), 0);
}

#[wasm_bindgen_test]
fn get_inscriptions_is_empty_array_for_fresh_wallet() {
    let ins = to_json(wallet().get_inscriptions().expect("inscriptions"));
    assert_eq!(ins.as_array().expect("array").len(), 0);
}

#[wasm_bindgen_test]
fn get_addresses_returns_canonical_address_fields() {
    // get_addresses returns an object/map of fields, not a bare array.
    let addrs = to_json(wallet().get_addresses().expect("addresses"));
    assert!(addrs.is_object(), "get_addresses returns a keyed object");
    let taproot = addrs["taproot"].as_str().expect("taproot field");
    assert!(
        taproot.starts_with("bcrt1p"),
        "expected regtest taproot, got {taproot}"
    );
    // Unified scheme aliases payment onto taproot without emitting retired Zinc field names.
    assert_eq!(addrs["payment"].as_str(), Some(taproot));
    assert!(addrs.get("vault").is_none());
    assert!(addrs.get("vaultPublicKey").is_none());
}

#[wasm_bindgen_test]
fn get_pairing_pubkey_hex_is_64_hex_chars() {
    let pk = wallet().get_pairing_pubkey_hex().expect("pairing pubkey");
    assert_eq!(pk.len(), 64);
    assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
}

// ---------------- state setters ----------------

#[wasm_bindgen_test]
fn derivation_mode_defaults_to_account_and_round_trips() {
    let w = wallet();
    assert_eq!(w.get_derivation_mode(), "account");
    w.set_derivation_mode("index").expect("set index");
    assert_eq!(w.get_derivation_mode(), "index");
}

#[wasm_bindgen_test]
fn set_derivation_mode_rejects_unknown_label() {
    assert!(wallet().set_derivation_mode("sideways").is_err());
}

#[wasm_bindgen_test]
fn payment_address_type_defaults_to_native_and_round_trips() {
    let w = wallet();
    assert_eq!(w.get_payment_address_type(), "native");
    w.set_payment_address_type("nested").expect("set nested");
    assert_eq!(w.get_payment_address_type(), "nested");
}
