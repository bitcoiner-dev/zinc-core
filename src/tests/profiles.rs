use crate::builder::{AddressScheme, Seed64, WalletBuilder};
use crate::error::ZincError;
use crate::keys::ZincMnemonic;
use bdk_wallet::bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn test_account_xpub(network: Network) -> String {
    test_account_xpub_for_purpose(network, 86)
}

fn test_account_xpub_for_purpose(network: Network, purpose: u32) -> String {
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let seed = mnemonic.to_seed("");
    let master = Xpriv::new_master(network, seed.as_ref()).expect("master xprv");
    let secp = Secp256k1::new();
    let coin_type = u32::from(network != Network::Bitcoin);
    let derivation_path = [
        ChildNumber::from_hardened_idx(purpose).expect("purpose"),
        ChildNumber::from_hardened_idx(coin_type).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
    ];
    let account_xprv = master
        .derive_priv(&secp, &derivation_path)
        .expect("account xprv");
    Xpub::from_priv(&secp, &account_xprv).to_string()
}

#[test]
fn test_watch_wallet_derivation() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let account_xpub = test_account_xpub(network);

    let seed_wallet = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("seed wallet");
    let watch_wallet = WalletBuilder::from_watch_only(network)
        .with_xpub(&account_xpub)
        .expect("valid xpub")
        .build()
        .expect("watch wallet");

    // Watch-only builders should default to dual mode for master public keys.
    assert!(!watch_wallet.is_unified());
    assert_eq!(
        watch_wallet.peek_taproot_address(0),
        seed_wallet.peek_taproot_address(0)
    );
    assert!(watch_wallet.peek_payment_address(0).is_some());
}

#[test]
fn test_watch_wallet_dual_xpub_parity() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let taproot_xpub = test_account_xpub_for_purpose(network, 86);
    let payment_xpub = test_account_xpub_for_purpose(network, 84);

    let seed_wallet = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("seed wallet");
    let watch_wallet = WalletBuilder::from_watch_only(network)
        .with_taproot_xpub(&taproot_xpub)
        .expect("valid taproot xpub")
        .with_payment_xpub(&payment_xpub)
        .expect("valid payment xpub")
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("watch wallet");

    assert_eq!(
        watch_wallet.peek_taproot_address(0),
        seed_wallet.peek_taproot_address(0)
    );
    assert_eq!(
        watch_wallet
            .peek_payment_address(0)
            .expect("payment address"),
        seed_wallet
            .peek_payment_address(0)
            .expect("payment address")
    );
}

#[test]
fn test_watch_address_mode_tracks_single_address() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let seed_wallet = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("seed wallet");
    let tracked_address = seed_wallet.peek_taproot_address(0).to_string();

    let watch_wallet = WalletBuilder::from_watch_only(network)
        .with_watch_address(&tracked_address)
        .expect("valid tracked address")
        .build()
        .expect("address watch wallet");

    assert!(watch_wallet.is_unified());
    assert_eq!(
        watch_wallet.peek_taproot_address(0).to_string(),
        tracked_address
    );
    assert_eq!(
        watch_wallet.collect_active_addresses(),
        vec![tracked_address.clone()]
    );

    let err = watch_wallet
        .sign_message(&tracked_address, "watch address cannot sign")
        .expect_err("watch address mode must not sign");
    assert_eq!(err, ZincError::CapabilityMissing.to_string());
}

#[test]
fn test_watch_address_mode_rejects_dual_scheme() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let seed_wallet = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("seed wallet");
    let tracked_address = seed_wallet.peek_taproot_address(0).to_string();

    let result = WalletBuilder::from_watch_only(network)
        .with_watch_address(&tracked_address)
        .expect("valid tracked address")
        .with_scheme(AddressScheme::Dual)
        .build();
    let err = match result {
        Ok(_) => panic!("dual scheme should not be allowed for address watch mode"),
        Err(e) => e,
    };
    assert!(err.contains("Address watch profiles support unified scheme only"));
}

#[test]
fn test_watch_address_mode_rejects_non_taproot_address() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let seed_wallet = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("seed wallet");
    let non_taproot_address = seed_wallet
        .peek_payment_address(0)
        .expect("payment address")
        .to_string();

    let result = WalletBuilder::from_watch_only(network).with_watch_address(&non_taproot_address);
    let err = match result {
        Ok(_) => panic!("non-taproot watch address should be rejected"),
        Err(e) => e,
    };
    assert!(err.contains("supports taproot"));
}

#[test]
fn test_watch_wallet_signing_gat() {
    let network = Network::Testnet;
    let account_xpub = test_account_xpub(network);
    let watch_wallet = WalletBuilder::from_watch_only(network)
        .with_xpub(&account_xpub)
        .expect("valid xpub")
        .build()
        .expect("watch wallet");

    let addr = watch_wallet.peek_taproot_address(0).to_string();
    let err = watch_wallet
        .sign_message(&addr, "zinc capability gate")
        .expect_err("watch profiles must not sign");
    assert_eq!(err, ZincError::CapabilityMissing.to_string());
}

#[test]
fn test_seed_wallet_full_capability() {
    let network = Network::Testnet;
    let mnemonic = ZincMnemonic::parse(TEST_MNEMONIC).expect("valid mnemonic");
    let seed = mnemonic.to_seed("");

    let wallet_from_mnemonic = WalletBuilder::from_mnemonic(network, &mnemonic)
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("wallet from mnemonic");
    let wallet_from_seed = WalletBuilder::from_seed(network, Seed64::from_array(*seed))
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("wallet from seed");

    assert_eq!(
        wallet_from_mnemonic.peek_taproot_address(0),
        wallet_from_seed.peek_taproot_address(0)
    );

    let addr = wallet_from_mnemonic.peek_taproot_address(0).to_string();
    let sig = wallet_from_mnemonic
        .sign_message(&addr, "zinc seed capability")
        .expect("seed profile signs");
    assert!(!sig.is_empty());
}
