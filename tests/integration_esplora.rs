#[cfg(not(target_arch = "wasm32"))]
use bdk_wallet::bitcoin::Network;
#[cfg(not(target_arch = "wasm32"))]
use zinc_core::builder::{Seed64, WalletBuilder};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
#[ignore = "requires local regtest esplora at http://localhost:50006/api"]
#[allow(clippy::expect_used)]
async fn test_esplora_sync_regtest() {
    let seed = [0u8; 64];
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .build()
        .expect("Should build wallet");

    // TDD: Verify Connection Check first
    let connected =
        zinc_core::builder::ZincWallet::check_connection("http://localhost:50006/api").await;
    assert!(
        connected,
        "Should verify connection to local Regtest Esplora"
    );

    // TDD: Verify Sync
    wallet
        .sync("http://localhost:50006/api")
        .await
        .expect("Sync should succeed");

    // We can't easily assert balance > 0 without funding the wallet first,
    // but success means the code paths executed without error.
}
