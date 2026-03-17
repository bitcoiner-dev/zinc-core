use bitcoin::Network;
use zinc_core::builder::{Seed64, SyncRequestType, WalletBuilder};

const TEST_SEED: [u8; 64] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
];

#[test]
fn test_sync_events_returned() {
    let builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED));
    let wallet = builder.build().expect("Should build wallet");

    // Fresh wallets should use full scan mode.
    assert!(
        wallet.needs_full_scan(),
        "New wallet should require full scan"
    );
}

#[test]
fn test_sync_strategy_choice() {
    let builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(TEST_SEED));
    let wallet = builder.build().expect("Should build wallet");

    let reqs = wallet.prepare_requests();
    match reqs.taproot {
        SyncRequestType::Full(_) => {}
        SyncRequestType::Incremental(_) => {
            panic!("Fresh wallet should start with a full scan request")
        }
    }
}
