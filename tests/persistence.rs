#![allow(clippy::expect_used)]
use bitcoin::Network;
use zinc_core::builder::{Seed64, WalletBuilder};

const TEST_SEED: [u8; 64] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
];

#[test]
fn test_fresh_wallet_persistence_has_descriptors() {
    let builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED));
    let wallet = builder.build().expect("Should build wallet");

    // export_changeset returns ZincPersistence directly now
    let persistence = wallet.export_changeset().expect("Should export changeset");

    let vault = persistence.taproot.expect("Should have vault changeset");
    assert!(
        vault.descriptor.is_some(),
        "Fresh persistence MUST include external descriptor"
    );
    assert!(
        vault.change_descriptor.is_some(),
        "Fresh persistence MUST include internal descriptor"
    );
    assert!(
        vault.network.is_some(),
        "Fresh persistence MUST include network"
    );

    // Check genesis hash presence (LocalChain)
    assert!(
        vault.local_chain.blocks.contains_key(&0),
        "Fresh persistence MUST include genesis block hash"
    );
}

#[test]
fn test_round_trip_persistence() {
    // 1. Create Wallet A
    let builder_a = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED));
    let wallet_a = builder_a.build().expect("Should build wallet A");
    let persistence_a = wallet_a.export_changeset().expect("Should export A");
    let json_a = serde_json::to_string(&persistence_a).expect("Should serialize");

    // 2. Create Wallet B FROM Wallet A's persistence
    let builder_b = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED))
        .with_persistence(&json_a)
        .expect("Should accept persistence");

    let wallet_b = builder_b
        .build()
        .expect("Should build wallet B from persistence");

    // 3. Verify Wallet B works (sanity check)
    assert_eq!(
        wallet_a.is_unified(),
        wallet_b.is_unified(),
        "Restored wallet should match scheme"
    );
}

#[test]
fn test_persistence_preservation() {
    // 1. Create Wallet A & Export
    let builder_a = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED));
    let wallet_a = builder_a.build().expect("Should build wallet A");
    let persistence_a = wallet_a.export_changeset().expect("Should export A");
    let json_a = serde_json::to_string(&persistence_a).expect("Should serialize");

    // 2. Load Wallet B from that persistence
    let builder_b = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED))
        .with_persistence(&json_a)
        .expect("Should accept persistence");
    let wallet_b = builder_b.build().expect("Should build wallet B");

    // 3. IMMEDIATELY Export from Wallet B (without doing anything)
    // If our logic is "only export changes", this would likely be empty/missing descriptors
    // If our logic is "export merged state", this should be identical (or superset) of json_a
    let persistence_b = wallet_b.export_changeset().expect("Should export B");

    let vault_b = persistence_b.taproot.expect("Should have vault data");

    // 4. ASSERT that Wallet B's export STILL has the descriptors
    assert!(
        vault_b.descriptor.is_some(),
        "Restored wallet export MUST preserve descriptors"
    );
    assert!(
        vault_b.change_descriptor.is_some(),
        "Restored wallet export MUST preserve change descriptors"
    );
    assert!(
        vault_b.local_chain.blocks.contains_key(&0),
        "Restored wallet export MUST preserve genesis block"
    );
}
