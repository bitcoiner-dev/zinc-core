#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used)]

use bitcoin::Network;
use zinc_core::builder::{AddressScheme, CreatePsbtRequest, Seed64, WalletBuilder};

// ============================================================================
// SEND FLOW TESTS - TDD
// These tests are written FIRST, before the implementation.
// ============================================================================

/// Test that we can create a PSBT for a basic send.
/// RED: This test will fail until create_psbt is implemented.
#[test]
fn test_create_psbt_basic() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::Mnemonic::parse(phrase)
        .expect("valid mnemonic")
        .to_seed("");

    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("wallet build");

    // BYPASS SAFETY LOCK: Mark ordinals as verified (0 inscriptions)
    wallet.apply_verified_ordinals_update(vec![], std::collections::HashSet::new(), vec![]);

    // For this test to pass, wallet needs UTXOs.
    // In a real scenario, we'd fund it first via regtest.
    // For now, test the error case for insufficient funds.

    // Target address (valid regtest address)
    let recipient = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let amount_sats = 10_000;
    let fee_rate = 1; // 1 sat/vB

    let request = CreatePsbtRequest::from_parts(recipient, amount_sats, fee_rate)
        .expect("valid request parts");
    let result = wallet.create_psbt_base64(&request);

    // For an unfunded wallet, we expect an error about insufficient funds
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Insufficient")
            || err_msg.contains("insufficient")
            || err_msg.contains("funds"),
        "Expected insufficient funds error, got: {err_msg}"
    );
}

/// Test that create_psbt validates addresses correctly.
#[test]
fn test_create_psbt_invalid_address() {
    // Invalid address
    let recipient = "not-a-valid-address";
    let amount_sats = 10_000;
    let fee_rate = 1;

    let result = CreatePsbtRequest::from_parts(recipient, amount_sats, fee_rate);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid address"),
        "Expected invalid address error, got: {err_msg}"
    );
}

/// Test that create_psbt rejects wrong network addresses.
#[test]
fn test_create_psbt_wrong_network() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::Mnemonic::parse(phrase)
        .expect("valid mnemonic")
        .to_seed("");

    // Wallet on regtest
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("wallet build");

    // BYPASS SAFETY LOCK: Mark ordinals as verified (0 inscriptions)
    wallet.apply_verified_ordinals_update(vec![], std::collections::HashSet::new(), vec![]);

    // Mainnet address (wrong network)
    let recipient = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let amount_sats = 10_000;
    let fee_rate = 1;

    let request = CreatePsbtRequest::from_parts(recipient, amount_sats, fee_rate)
        .expect("request should parse for wrong-network assertion");
    let result = wallet.create_psbt_base64(&request);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Network") || err_msg.contains("network"),
        "Expected network mismatch error, got: {err_msg}"
    );
}

/// Test sign_psbt with a pre-constructed PSBT.
/// This requires a valid unsigned PSBT to sign.
#[test]
fn test_sign_psbt_invalid_base64() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::Mnemonic::parse(phrase)
        .expect("valid mnemonic")
        .to_seed("");

    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("wallet build");

    // Invalid base64
    let result = wallet.sign_psbt("not-valid-base64!!!", None);

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("base64") || err_msg.contains("Invalid"),
        "Expected base64 error, got: {err_msg}"
    );
}

#[test]
#[allow(deprecated)]
fn test_create_psbt_wrapper_matches_typed_path_error_surface() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::Mnemonic::parse(phrase)
        .expect("valid mnemonic")
        .to_seed("");

    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("wallet build");

    wallet.apply_verified_ordinals_update(vec![], std::collections::HashSet::new(), vec![]);

    let recipient = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let amount_sats = 10_000;
    let fee_rate = 1;

    let request =
        CreatePsbtRequest::from_parts(recipient, amount_sats, fee_rate).expect("valid request");
    let typed_err = wallet
        .create_psbt_base64(&request)
        .expect_err("empty wallet should fail");
    let wrapper_err = wallet
        .create_psbt(recipient, amount_sats, fee_rate)
        .expect_err("empty wallet should fail");

    assert_eq!(typed_err.to_string(), wrapper_err);
}
