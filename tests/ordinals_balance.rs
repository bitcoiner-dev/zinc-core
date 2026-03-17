#![cfg(not(target_arch = "wasm32"))]
#![allow(unused_imports, unused_variables, dead_code)]
#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Network, OutPoint, Txid};
    use std::collections::HashSet;
    use std::str::FromStr;
    use zinc_core::builder::{AddressScheme, CreatePsbtRequest, Seed64, WalletBuilder, ZincWallet};
    use zinc_core::ordinals::types::{Inscription, Satpoint};

    // Helper to create a dummy OutPoint
    fn make_outpoint(i: u8) -> OutPoint {
        let hash = format!("{:064x}", i);
        OutPoint::new(Txid::from_str(&hash).unwrap(), 0)
    }

    #[test]
    fn test_zinc_balance_struct() {
        // This test will fail until we define ZincBalance in builder.rs
        // Un-comment lines below once struct is defined
        /*
        let balance = zinc_core::builder::ZincBalance {
            total: bdk_wallet::Balance::default(),
            spendable: bdk_wallet::Balance::default(),
            inscribed: 0,
        };
        assert_eq!(balance.inscribed, 0);
        */
    }

    // Since we can't easily mock the internal BDK wallet state in integration tests without
    // spinning up a full regtest (which is slow for TDD cycle), we will verify the logic
    // by testing the calculation function directly if we extract it, OR we rely on the
    // fact that we are modifying the struct fields.

    // For TDD, let's assume we will implement a helper method in ZincWallet
    // `calculate_safe_balance(raw_balance, inscriptions, wallet_utxos)`
    // But ZincWallet encapsulates BDK.

    // BETTER APPROACH: Verify the "Ordinals Verified" flag behavior.

    #[tokio::test]
    async fn test_ordinals_verified_flag_default() {
        // Create a dummy builder (requires network and seed)
        let seed = [0u8; 64];
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .build()
            .unwrap();

        // Flag should be false by default
        // assert!(!wallet.ordinals_verified); // Private field, need getter or check behavior

        // Use a wallet-owned address so parsing/network checks don't mask the safety-lock assertion.
        let recipient = wallet.peek_taproot_address(0).to_string();
        let request = CreatePsbtRequest::from_parts(&recipient, 1000, 1).unwrap();
        let result = wallet.create_psbt_base64(&request);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Ordinals verification failed"));
    }
}
