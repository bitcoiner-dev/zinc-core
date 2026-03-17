#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use zinc_core::ZincWasmWallet;

#[wasm_bindgen_test]
fn test_get_accounts_returns_public_keys() {
    // 1. Setup
    // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    // Seed is deterministic.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 2. Initialize Wallet (Unified Scheme)
    let wallet = ZincWasmWallet::new(
        "regtest",
        phrase,
        Some("unified".to_string()),
        None,
        Some(0),
    )
    .expect("Failed to create wallet");

    // 3. Get Accounts
    let accounts_js = wallet.get_accounts(1).expect("get_accounts failed");

    // 4. Deserialize and Verify
    let accounts: Vec<serde_json::Value> =
        serde_wasm_bindgen::from_value(accounts_js).expect("Failed to deserialize accounts");

    assert_eq!(accounts.len(), 1);
    let acc0 = &accounts[0];

    // Check Vault Public Key
    let vault_pub = acc0
        .get("taprootPublicKey")
        .expect("Missing taprootPublicKey");
    assert!(vault_pub.is_string());
    let vault_hex = vault_pub.as_str().unwrap();
    assert_eq!(
        vault_hex.len(),
        64,
        "Vault pubkey should be 32 bytes hex (x-only)"
    );

    // Unified -> Payment Public Key should be None (as per our impl, we return derived if !unified, else None)
    // Wait, let's double check implementation logic in lib.rs:
    // "paymentPublicKey": payment_pubkey_hex
    // where payment_pubkey_hex is None if unified.
    // So for "unified", we expect paymentPublicKey to be null (or missing depending on serialization).
    let payment_pub = acc0.get("paymentPublicKey");
    // serde_json usually serializes Option::None as null
    assert!(
        payment_pub.is_none() || payment_pub.unwrap().is_null(),
        "Unified payment pubkey should be null"
    );
}

#[wasm_bindgen_test]
fn test_get_accounts_dual_returns_public_keys() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 2. Initialize Wallet (Dual Scheme)
    let wallet = ZincWasmWallet::new("regtest", phrase, Some("dual".to_string()), None, Some(0))
        .expect("Failed to create wallet");

    let accounts_js = wallet.get_accounts(1).expect("get_accounts failed");
    let accounts: Vec<serde_json::Value> = serde_wasm_bindgen::from_value(accounts_js).unwrap();
    let acc0 = &accounts[0];

    // Vault
    let vault_pub = acc0
        .get("taprootPublicKey")
        .expect("Missing taprootPublicKey");
    assert_eq!(vault_pub.as_str().unwrap().len(), 64);

    // Payment (should be present for dual)
    let payment_pub = acc0
        .get("paymentPublicKey")
        .expect("Missing paymentPublicKey");
    assert!(payment_pub.is_string());
    let pay_hex = payment_pub.as_str().unwrap();
    assert_eq!(
        pay_hex.len(),
        66,
        "Payment pubkey should be 33 bytes hex (compressed)"
    );
}
