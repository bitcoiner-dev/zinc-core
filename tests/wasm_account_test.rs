#![cfg(target_arch = "wasm32")]

use wasm_bindgen::JsValue;
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

#[wasm_bindgen_test]
fn test_get_rune_balances_returns_stable_empty_array_shape() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = ZincWasmWallet::new(
        "regtest",
        phrase,
        Some("unified".to_string()),
        None,
        Some(0),
    )
    .expect("Failed to create wallet");

    let balances_js = wallet
        .get_rune_balances()
        .expect("get_rune_balances should succeed");
    let balances: Vec<serde_json::Value> =
        serde_wasm_bindgen::from_value(balances_js).expect("balances should deserialize");
    assert!(
        balances.is_empty(),
        "fresh wallet should expose an empty rune balance list"
    );
}

#[wasm_bindgen_test]
fn test_shared_receiver_methods_do_not_alias_trap() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = ZincWasmWallet::new(
        "regtest",
        phrase,
        Some("unified".to_string()),
        None,
        Some(0),
    )
    .expect("Failed to create wallet");

    wallet
        .set_scheme("dual")
        .expect("set_scheme should work from shared receiver");
    wallet
        .set_active_account(1)
        .expect("set_active_account should work from shared receiver");
    wallet
        .set_network("signet")
        .expect("set_network should work from shared receiver");
    wallet
        .set_network("regtest")
        .expect("set_network should switch back to regtest");

    let sign_err = wallet
        .sign_psbt("not-a-valid-psbt", JsValue::NULL)
        .expect_err("invalid PSBT should error");
    let err_text = sign_err.as_string().unwrap_or_default();
    assert!(
        !err_text.contains("recursive use of an object"),
        "sign_psbt should not surface wasm aliasing trap"
    );
}

#[wasm_bindgen_test]
fn test_account_and_address_views_stay_coherent_after_switches() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = ZincWasmWallet::new(
        "regtest",
        phrase,
        Some("unified".to_string()),
        None,
        Some(0),
    )
    .expect("Failed to create wallet");

    wallet
        .set_scheme("dual")
        .expect("set_scheme should succeed");
    wallet
        .set_active_account(1)
        .expect("set_active_account should succeed");
    wallet
        .set_network("signet")
        .expect("set_network should succeed");
    wallet
        .set_network("regtest")
        .expect("set_network should return to regtest");

    let addrs_js = wallet.get_addresses().expect("get_addresses failed");
    let addrs: serde_json::Value =
        serde_wasm_bindgen::from_value(addrs_js).expect("address payload should deserialize");
    assert_eq!(addrs["account_index"].as_u64(), Some(1));

    let accounts_js = wallet.get_accounts(3).expect("get_accounts failed");
    let accounts: Vec<serde_json::Value> =
        serde_wasm_bindgen::from_value(accounts_js).expect("accounts should deserialize");
    let active_account = accounts
        .iter()
        .find(|acc| acc.get("index").and_then(|v| v.as_u64()) == Some(1))
        .expect("account index 1 should exist");

    let account_taproot = active_account
        .get("taprootAddress")
        .and_then(|v| v.as_str())
        .expect("account taprootAddress should be a string");
    let current_taproot = addrs
        .get("taproot")
        .and_then(|v| v.as_str())
        .expect("current taproot should be a string");

    assert_eq!(
        account_taproot, current_taproot,
        "active account preview should match get_addresses output"
    );
}

#[wasm_bindgen_test]
fn test_index_mode_addresses_follow_active_account() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet = ZincWasmWallet::new("regtest", phrase, Some("dual".to_string()), None, Some(0))
        .expect("Failed to create wallet");

    wallet
        .set_derivation_mode("index")
        .expect("set_derivation_mode should succeed");
    wallet
        .set_active_account(2)
        .expect("set_active_account should succeed");

    let addrs_js = wallet.get_addresses().expect("get_addresses failed");
    let addrs: serde_json::Value =
        serde_wasm_bindgen::from_value(addrs_js).expect("address payload should deserialize");
    assert_eq!(addrs["account_index"].as_u64(), Some(2));

    let accounts_js = wallet.get_accounts(3).expect("get_accounts failed");
    let accounts: Vec<serde_json::Value> =
        serde_wasm_bindgen::from_value(accounts_js).expect("accounts should deserialize");
    let active_account = accounts
        .iter()
        .find(|acc| acc.get("index").and_then(|v| v.as_u64()) == Some(2))
        .expect("account index 2 should exist");

    let account_taproot = active_account
        .get("taprootAddress")
        .and_then(|v| v.as_str())
        .expect("account taprootAddress should be a string");
    let current_taproot = addrs
        .get("taproot")
        .and_then(|v| v.as_str())
        .expect("current taproot should be a string");
    assert_eq!(
        account_taproot, current_taproot,
        "index-mode active taproot should match get_addresses output"
    );

    let account_payment = active_account
        .get("paymentAddress")
        .and_then(|v| v.as_str())
        .expect("account paymentAddress should be a string");
    let current_payment = addrs
        .get("payment")
        .and_then(|v| v.as_str())
        .expect("current payment should be a string");
    assert_eq!(
        account_payment, current_payment,
        "index-mode active payment should match get_addresses output"
    );
}
