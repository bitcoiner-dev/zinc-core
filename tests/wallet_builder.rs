#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used)]
use bitcoin::Network;
use zinc_core::builder::{AddressScheme, Seed64, WalletBuilder, ZincWallet};

#[test]
fn test_builder_unified_scheme_defaults() {
    let seed = [0u8; 64]; // Mock seed
    let builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed));

    // Default should be Unified
    let mut wallet: ZincWallet = builder.build().expect("Should build wallet");

    // Unified means vault and payment are the same underlying mechanism (or payment is None/aliased)
    // For this implementation, let's say:
    // Unified: Vault (TR) handles everything. Payment accessor returns vault address.

    assert!(wallet.is_unified());

    let vault_addr = wallet
        .next_taproot_address()
        .expect("Should get vault address");
    let payment_addr = wallet
        .get_payment_address()
        .expect("Should get payment address");

    // In a stateful wallet, getting an address increments the index.
    // So vault_addr (index 0) and payment_addr (index 1) will be different.
    // But both must be Taproot (bcrt1p) to prove they use the same Vault descriptor.

    // Check Vault Address
    assert!(
        vault_addr.to_string().starts_with("bcrt1p"),
        "Unified vault address must be Taproot"
    );

    // Check Payment Address
    assert!(
        payment_addr.to_string().starts_with("bcrt1p"),
        "Unified payment address must be Taproot (same as vault)"
    );

    let taproot_peek = wallet.peek_taproot_address(4);
    let payment_peek = wallet
        .peek_payment_address(4)
        .expect("Unified mode should expose payment as taproot");
    assert_eq!(
        taproot_peek, payment_peek,
        "Unified mode payment address must resolve to taproot branch"
    );

    let account = wallet
        .get_accounts(1)
        .into_iter()
        .next()
        .expect("Should include first account");
    assert_eq!(
        account.payment_address.as_deref(),
        Some(account.taproot_address.as_str()),
        "Unified account payment address should mirror taproot address"
    );
    assert_eq!(
        account.payment_public_key.as_deref(),
        Some(account.taproot_public_key.as_str()),
        "Unified account payment pubkey should mirror taproot pubkey"
    );
}

#[test]
fn test_builder_dual_scheme() {
    let seed = [0u8; 64];
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .build()
        .expect("Should build dual wallet");

    assert!(!wallet.is_unified());

    let vault_addr = wallet
        .next_taproot_address()
        .expect("Should get vault address");
    let payment_addr = wallet
        .get_payment_address()
        .expect("Should get payment address");

    assert_ne!(
        vault_addr, payment_addr,
        "In dual mode, addresses MUST be different"
    );

    // Vault -> Taproot (bcrt1p)
    assert!(
        vault_addr.to_string().starts_with("bcrt1p"),
        "Vault address must be Taproot (starts with bcrt1p)"
    );

    // Payment -> SegWit v0 (bcrt1q)
    assert!(
        payment_addr.to_string().starts_with("bcrt1q"),
        "Payment address must be SegWit v0 (starts with bcrt1q)"
    );
}

#[test]
fn account_preview_pages_preserve_identity_and_do_not_reveal_addresses() {
    for mode in [
        zinc_core::DerivationMode::Account,
        zinc_core::DerivationMode::Index,
    ] {
        let wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7; 64]))
            .with_scheme(AddressScheme::Dual)
            .with_derivation_mode(mode)
            .build()
            .expect("wallet");
        let before = wallet.peek_taproot_address(0);
        let expected = wallet.get_accounts(26);
        for start in [0, 1, 8, 24] {
            let page = wallet.get_account_range(start, 2).expect("bounded page");
            assert_eq!(page.len(), 2);
            for (offset, actual) in page.iter().enumerate() {
                let expected = &expected[start as usize + offset];
                assert_eq!(actual.index, expected.index);
                assert_eq!(actual.taproot_address, expected.taproot_address);
                assert_eq!(actual.payment_address, expected.payment_address);
                assert_eq!(actual.taproot_public_key, expected.taproot_public_key);
                assert_eq!(actual.payment_public_key, expected.payment_public_key);
            }
        }
        assert_eq!(wallet.peek_taproot_address(0), before);
        for (start, count) in [(0, 0), (0, 9), (99, 2), (100, 1), (u32::MAX, 1)] {
            assert!(wallet.get_account_range(start, count).is_err());
        }
        assert_eq!(
            wallet.get_account_range(99, 1).expect("last account")[0].index,
            99
        );
    }
}
