use bitcoin::Network;
use zinc_core::{AddressScheme, Seed64, WalletBuilder};

#[test]
fn test_unified_multi_account() {
    let seed = [0u8; 64]; // deterministic seed
                          // Account 0
    let mut wallet0 = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .with_account_index(0)
        .build()
        .expect("failed to build wallet");

    let addr0 = wallet0.next_taproot_address().unwrap().to_string();

    // Account 1
    let mut wallet1 = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .with_account_index(1)
        .build()
        .expect("failed to build wallet");

    let addr1 = wallet1.next_taproot_address().unwrap().to_string();

    assert_ne!(
        addr0, addr1,
        "Account 0 and 1 should have different addresses"
    );
}

#[test]
fn test_dual_multi_account() {
    let seed = [0u8; 64];
    // Account 1 (Dual)
    let mut wallet1 = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_account_index(1)
        .build()
        .expect("failed to build wallet");

    let vault1 = wallet1.next_taproot_address().unwrap().to_string();
    let payment1 = wallet1.get_payment_address().unwrap().to_string();

    // Vault (Taproot) starts with bcrt1p
    assert!(vault1.starts_with("bcrt1p"));
    // Payment (SegWit) starts with bcrt1q
    assert!(payment1.starts_with("bcrt1q"));
}
