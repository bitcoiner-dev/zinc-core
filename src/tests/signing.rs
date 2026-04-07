#[cfg(test)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, SignOptions, WalletBuilder};
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut, Txid};
    use bdk_wallet::chain::ConfirmationBlockTime;
    use bdk_wallet::KeychainKind;
    use bitcoin::psbt::Psbt;
    use std::str::FromStr;

    // Helper to create a dummy transaction for UTXO creation (copied from balance.rs)
    fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid;
        let dummy_txid = Txid::from_byte_array(hash_bytes);

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
    fn test_sign_specific_inputs() {
        // 1. Setup Wallet
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        // 2. Insert 3 UTXOs
        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();

        let tx1 = create_dummy_tx(10_000, script.clone(), 1);
        let tx2 = create_dummy_tx(20_000, script.clone(), 2);
        let tx3 = create_dummy_tx(30_000, script.clone(), 3);

        for tx in [&tx1, &tx2, &tx3] {
            let _ = graph.insert_tx(tx.clone());
            let _ = graph.insert_anchor(
                tx.compute_txid(),
                ConfirmationBlockTime {
                    block_id: bdk_wallet::chain::BlockId {
                        height: 100,
                        hash: dummy_block_hash,
                    },
                    confirmation_time: 1000,
                },
            );
        }

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        // 3. Create a PSBT that spends all 3 inputs
        // We'll manually construct a PSBT since create_psbt relies on BDK coin selection which might not pick all 3.
        // Or simpler: create a manual transaction with 3 inputs referencing our UTXOs, then convert to PSBT.

        let inputs = vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx1.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx2.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx3.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            },
        ];

        let output = TxOut {
            value: Amount::from_sat(59_000), // Fee of 1000
            script_pubkey: script.clone(),
        };

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: vec![output],
        };

        // Create PSBT from unsigned tx
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        // Add witness_utxo to PSBT inputs (required for signing Segwit/Taproot)
        psbt.inputs[0].witness_utxo = Some(tx1.output[0].clone());
        psbt.inputs[1].witness_utxo = Some(tx2.output[0].clone());
        psbt.inputs[2].witness_utxo = Some(tx3.output[0].clone());

        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        // 4. Test: Sign ONLY Input 1 (Index 1)
        let options = SignOptions {
            sign_inputs: Some(vec![1]),
            sighash: None,
            finalize: false,
        };

        let signed_base64 = builder
            .sign_psbt(&psbt_base64, Some(options))
            .expect("Signing failed");

        let signed_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_base64)
            .unwrap();
        let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();

        // Assertions
        // Input 0: Should NOT be final script witness (implementation detail of BDK default signing)
        // Actually BDK putting signature usually results in partial_sigs or final_script_witness.
        // Since we are using taproot (Unified mode default), we expect tap_key_sig or similar.

        // Check if Input 1 is signed
        let has_sig_1 = signed_psbt.inputs[1].final_script_witness.is_some()
            || signed_psbt.inputs[1].tap_key_sig.is_some();
        assert!(has_sig_1, "Input 1 should be signed");

        // Check if Input 0 is NOT signed
        let has_sig_0 = signed_psbt.inputs[0].final_script_witness.is_some()
            || signed_psbt.inputs[0].tap_key_sig.is_some();
        assert!(!has_sig_0, "Input 0 should NOT be signed");

        // Check if Input 2 is NOT signed
        let has_sig_2 = signed_psbt.inputs[2].final_script_witness.is_some()
            || signed_psbt.inputs[2].tap_key_sig.is_some();
        assert!(!has_sig_2, "Input 2 should NOT be signed");
    }

    #[test]
    fn test_sign_psbt_leaves_partial_sigs() {
        // 1. Setup Wallet
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified) // Taproot
            .build()
            .unwrap();

        let addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        // 2. Insert 1 UTXO
        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let tx1 = create_dummy_tx(10_000, script.clone(), 1);

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

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        // 3. Create PSBT
        let inputs = vec![bdk_wallet::bitcoin::TxIn {
            previous_output: bdk_wallet::bitcoin::OutPoint::new(tx1.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bdk_wallet::bitcoin::Witness::default(),
        }];

        let output = TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: script.clone(),
        };

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: vec![output],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(tx1.output[0].clone()); // Needed for signing

        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        // 4. Sign
        let signed_base64 = builder
            .sign_psbt(&psbt_base64, None)
            .expect("Signing failed");
        let signed_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_base64)
            .unwrap();
        let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();

        // 5. Assert: MUST be Partially Signed (Xverse style)
        // Should NOT have final witness
        assert!(
            signed_psbt.inputs[0].final_script_witness.is_none(),
            "Should NOT have final_script_witness (must be partial)"
        );

        // Should HAVE tap_key_sig
        assert!(
            signed_psbt.inputs[0].tap_key_sig.is_some(),
            "Should HAVE tap_key_sig"
        );
    }

    #[test]
    fn test_rejects_disallowed_sighash_types() {
        let seed = [42u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let tx = create_dummy_tx(10_000, script.clone(), 17);
        let _ = graph.insert_tx(tx.clone());
        let _ = graph.insert_anchor(
            tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1000,
            },
        );

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(tx.output[0].clone());
        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        for disallowed_sighash in [2u8, 3u8, 129u8] {
            let err = builder
                .sign_psbt(
                    &psbt_base64,
                    Some(SignOptions {
                        sign_inputs: Some(vec![0]),
                        sighash: Some(disallowed_sighash),
                        finalize: false,
                    }),
                )
                .expect_err("disallowed sighash should be rejected");

            assert!(
                err.contains("Sighash type is not allowed"),
                "unexpected error for sighash {disallowed_sighash}: {err}"
            );
        }
    }

    #[test]
    fn test_rejects_out_of_range_sign_inputs() {
        let seed = [11u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let tx = create_dummy_tx(12_000, script.clone(), 19);
        let _ = graph.insert_tx(tx.clone());
        let _ = graph.insert_anchor(
            tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1000,
            },
        );

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(11_000),
                script_pubkey: script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(tx.output[0].clone());
        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        let err = builder
            .sign_psbt(
                &psbt_base64,
                Some(SignOptions {
                    sign_inputs: Some(vec![1]),
                    sighash: None,
                    finalize: false,
                }),
            )
            .expect_err("out-of-range sign input should be rejected");

        assert!(
            err.contains("out of bounds"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_rejects_requested_foreign_input_that_wallet_cannot_sign() {
        let seed = [88u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let my_addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let my_script = my_addr.script_pubkey();
        let mut foreign_builder =
            WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7u8; 64]))
                .with_scheme(AddressScheme::Unified)
                .build()
                .unwrap();
        let foreign_script = foreign_builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();

        let mut graph = bdk_wallet::chain::TxGraph::default();
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let my_tx = create_dummy_tx(20_000, my_script.clone(), 23);
        let _ = graph.insert_tx(my_tx.clone());
        let _ = graph.insert_anchor(
            my_tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: dummy_block_hash,
                },
                confirmation_time: 1000,
            },
        );

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        let update = bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        };
        builder.vault_wallet.apply_update(update).unwrap();

        let foreign_prev_tx = create_dummy_tx(15_000, foreign_script.clone(), 24);

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bdk_wallet::bitcoin::TxIn {
                    previous_output: bdk_wallet::bitcoin::OutPoint::new(
                        foreign_prev_tx.compute_txid(),
                        0,
                    ),
                    script_sig: ScriptBuf::new(),
                    sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bdk_wallet::bitcoin::Witness::default(),
                },
                bdk_wallet::bitcoin::TxIn {
                    previous_output: bdk_wallet::bitcoin::OutPoint::new(my_tx.compute_txid(), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bdk_wallet::bitcoin::Witness::default(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(34_000),
                script_pubkey: my_script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(foreign_prev_tx.output[0].clone());
        psbt.inputs[1].witness_utxo = Some(my_tx.output[0].clone());
        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        let err = builder
            .sign_psbt(
                &psbt_base64,
                Some(SignOptions {
                    sign_inputs: Some(vec![0]),
                    sighash: None,
                    finalize: false,
                }),
            )
            .expect_err("foreign requested input should be rejected");

        assert!(
            err.contains("was not signed by this wallet"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_rejects_requested_input_missing_utxo_metadata() {
        let seed = [90u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let my_addr = builder
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let my_script = my_addr.script_pubkey();
        let unknown_txid =
            Txid::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(unknown_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: my_script,
            }],
        };
        let psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        let err = builder
            .sign_psbt(
                &psbt_base64,
                Some(SignOptions {
                    sign_inputs: Some(vec![0]),
                    sighash: None,
                    finalize: false,
                }),
            )
            .expect_err("requested input without UTXO metadata should be rejected");

        assert!(
            err.contains("Requested input #0 is missing UTXO metadata"),
            "unexpected error message: {err}"
        );
    }
}
