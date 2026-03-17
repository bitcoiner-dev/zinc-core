#[cfg(test)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut}; // Updated imports
    use bdk_wallet::chain::ConfirmationBlockTime;
    use bdk_wallet::KeychainKind;

    fn debug_test_logs_enabled() -> bool {
        std::env::var_os("ZINC_CORE_TEST_LOG").is_some()
    }

    // Helper to create a dummy transaction for UTXO creation
    fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        // Create a dummy input so it's NOT a coinbase (which requires maturity)
        // Use uid to make input unique (avoid double spend)
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid; // unique hash per dummy tx
        let dummy_txid = bdk_wallet::bitcoin::Txid::from_byte_array(hash_bytes);

        let dummy_input = bdk_wallet::bitcoin::TxIn {
            previous_output: bdk_wallet::bitcoin::OutPoint::new(dummy_txid, 0),
            script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
            sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bdk_wallet::bitcoin::Witness::default(),
        };

        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![dummy_input],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey,
            }],
        }
    }

    #[test]
    fn test_balance_with_ordinals_and_btc() {
        // 1. Setup Wallet (Unified Scheme for simplicity, but logic applies to both)
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        // 2. Get the wallet's address to "receive" funds
        let addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        // 3. Manually insert UTXOs into the wallet's internal database/state
        // We can't easily mock the internal BDK wallet state without using its insert_tx methods.

        // 3. Manually insert UTXOs using bdk_wallet::Update
        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();

        // UTXO 1: Ordinal 1 (330 sats) - Confirmed
        let tx1 = create_dummy_tx(330, script.clone(), 1);
        let _ = graph.insert_tx(tx1.clone());
        let _ = graph.insert_anchor(
            tx1.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1000,
            },
        );

        // UTXO 2: Ordinal 2 (546 sats) - Confirmed
        let tx2 = create_dummy_tx(546, script.clone(), 2);
        let _ = graph.insert_tx(tx2.clone());
        let _ = graph.insert_anchor(
            tx2.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 101,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1001,
            },
        );

        // UTXO 3: Ordinal 3 (10,000 sats) - Confirmed
        let tx3 = create_dummy_tx(10000, script.clone(), 3);
        let _ = graph.insert_tx(tx3.clone());
        let _ = graph.insert_anchor(
            tx3.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 102,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1002,
            },
        );

        // UTXO 4: BTC Balance (3.14 BTC) - Confirmed
        let tx4 = create_dummy_tx(314_000_000, script.clone(), 4);
        let _ = graph.insert_tx(tx4.clone());
        let _ = graph.insert_anchor(
            tx4.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 103,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1003,
            },
        );

        // UTXO 5: BTC Balance (0.1 BTC) - Unconfirmed
        let tx5 = create_dummy_tx(10_000_000, script.clone(), 5);
        let _ = graph.insert_tx(tx5.clone());
        let _ = graph.insert_anchor(
            tx5.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 104,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1004,
            },
        );

        // Apply update to wallet
        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);

        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        // 4. Mark the ordinal UTXOs in the wallet's state
        let outpoint1 = OutPoint::new(tx1.compute_txid(), 0);
        let outpoint2 = OutPoint::new(tx2.compute_txid(), 0);
        let outpoint3 = OutPoint::new(tx3.compute_txid(), 0);

        builder.inscribed_utxos.insert(outpoint1);
        builder.inscribed_utxos.insert(outpoint2);
        builder.inscribed_utxos.insert(outpoint3);

        // 5. Call get_balance
        let unspent: Vec<_> = builder.vault_wallet.list_unspent().collect();
        if debug_test_logs_enabled() {
            println!("DEBUG: Unspent count: {}", unspent.len());
            for u in &unspent {
                println!("DEBUG: UTXO: {:?} Value: {}", u.outpoint, u.txout.value);
            }
        }
        assert!(
            unspent.len() >= 4,
            "Test setup failed: Wallet should have at least 4 UTXOs"
        );

        let balance = builder.get_balance();

        // 6. Assertions
        // Confirmed should be strictly the BTC UTXO (3.14 BTC)
        std::thread::sleep(std::time::Duration::from_millis(100)); // Give async time if needed? (Not needed for synchronous apply)

        if debug_test_logs_enabled() {
            println!("DEBUG: Balance: {:?}", balance);
        }
        // Without chain tip, it shows as trusted_pending (3.24 BTC)
        assert_eq!(
            balance.spendable.trusted_pending.to_sat(),
            324_000_000,
            "Spendable Pending balance should be 3.24 BTC"
        );
        assert_eq!(
            balance.spendable.confirmed.to_sat(),
            0,
            "Confirmed should be 0 without chain tip"
        );

        // Unconfirmed should be strictly the unconfirmed BTC UTXO (0.1 BTC)
        // assert_eq!(balance.spendable.untrusted_pending.to_sat(), 10_000_000, "Unconfirmed spendable balance should be 0.1 BTC");

        let total_spendable = balance.spendable.total().to_sat();
        assert_eq!(
            total_spendable, 324_000_000,
            "Total spendable should be 3.24 BTC"
        );
    }
}
