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

    /// The wallet holds the true `TxOut` for its own UTXOs, so a PSBT that
    /// declares a different value for one of them is lying. The enrichment
    /// pass used to backfill only when BOTH UTXO fields were absent, so a
    /// declared `witness_utxo` was never compared against what we knew.
    #[test]
    fn rejects_witness_utxo_that_contradicts_a_wallet_owned_output() {
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

        let mut graph = bdk_wallet::chain::TxGraph::default();
        let tx1 = create_dummy_tx(10_000, script.clone(), 1);
        let _ = graph.insert_tx(tx1.clone());
        let _ = graph.insert_anchor(
            tx1.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: bdk_wallet::bitcoin::BlockHash::all_zeros(),
                },
                confirmation_time: 1000,
            },
        );
        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 5);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last_active,
            })
            .unwrap();

        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(tx1.compute_txid(), 0),
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
        // The UTXO is really 10,000 sats. Claim 500,000 — under the old code
        // the surplus would have been burned to miners as fee.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(500_000),
            script_pubkey: script,
        });

        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
        let err = builder
            .sign_psbt(&psbt_base64, None)
            .expect_err("an inflated value on a wallet-owned input must be refused");

        assert!(
            err.contains("declares a different value or script"),
            "unexpected error message: {err}"
        );
    }

    /// Build a single-leaf taptree whose leaf is `<key> OP_CHECKSIG`, rooted at
    /// `internal_key`. Returns (scriptPubKey, leaf script, control block).
    fn single_leaf_taptree(
        internal_key: bitcoin::secp256k1::XOnlyPublicKey,
        leaf_key: bitcoin::secp256k1::XOnlyPublicKey,
    ) -> (
        ScriptBuf,
        ScriptBuf,
        bdk_wallet::bitcoin::taproot::ControlBlock,
    ) {
        use bdk_wallet::bitcoin::taproot::{LeafVersion, TaprootBuilder};
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let leaf = bdk_wallet::bitcoin::script::Builder::new()
            .push_x_only_key(&leaf_key)
            .push_opcode(bdk_wallet::bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        (spk, leaf, control_block)
    }

    /// Assemble a one-input PSBT that presents `spk`/`leaf`/`control_block` as a
    /// reveal-shaped script-path input carrying the empty-fingerprint origin the
    /// custom signer keys off.
    fn reveal_shaped_psbt(
        wallet_key: bitcoin::secp256k1::XOnlyPublicKey,
        spk: ScriptBuf,
        leaf: ScriptBuf,
        control_block: bdk_wallet::bitcoin::taproot::ControlBlock,
        internal_key: bitcoin::secp256k1::XOnlyPublicKey,
    ) -> Psbt {
        use bdk_wallet::bitcoin::taproot::{LeafVersion, TapLeafHash};

        let prev_txid = Txid::from_byte_array([9u8; 32]);
        let unsigned_tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: bdk_wallet::bitcoin::OutPoint::new(prev_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: spk.clone(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk,
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf.clone(), LeafVersion::TapScript));

        // Empty [0,0,0,0] fingerprint: the marker the reveal signer keys off,
        // and entirely attacker-controlled.
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_key_origins.insert(
            wallet_key,
            (
                vec![leaf_hash],
                (
                    bdk_wallet::bitcoin::bip32::Fingerprint::from([0u8; 4]),
                    bdk_wallet::bitcoin::bip32::DerivationPath::default(),
                ),
            ),
        );
        psbt
    }

    fn wallet_taproot_x_only(
        builder: &crate::builder::ZincWallet,
    ) -> bitcoin::secp256k1::XOnlyPublicKey {
        let hex = builder.get_taproot_public_key(0).unwrap();
        bitcoin::secp256k1::XOnlyPublicKey::from_str(&hex).unwrap()
    }

    /// Signs input 0 and reports how many tap script sigs came back. `Err` when
    /// the wallet refused outright — its existing "requested input was not
    /// signed" guard fires when the reveal signer declines every leaf.
    fn sign_and_count_script_sigs(
        builder: &mut crate::builder::ZincWallet,
        psbt: &Psbt,
    ) -> Result<usize, String> {
        let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
        let signed = builder.sign_psbt(
            &psbt_base64,
            Some(SignOptions {
                sign_inputs: Some(vec![0]),
                sighash: None,
                finalize: false,
            }),
        )?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(signed)
            .unwrap();
        Ok(Psbt::deserialize(&bytes).unwrap().inputs[0]
            .tap_script_sigs
            .len())
    }

    /// The reveal signer must bind every leaf it signs to the prevout it is
    /// spending. Before this check the empty-fingerprint origin alone was
    /// treated as proof of ownership, so the wallet would sign an arbitrary
    /// tapscript against an arbitrary sighash — a blind-signing oracle.
    #[test]
    fn script_path_signer_binds_leaf_to_prevout() {
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let wallet_key = wallet_taproot_x_only(&builder);

        // Positive control: a real commit-shaped taptree rooted at our own key
        // with a leaf that requires our signature. This is the legitimate
        // inscription-reveal shape and must still be signed.
        let (spk, leaf, control_block) = single_leaf_taptree(wallet_key, wallet_key);
        let psbt = reveal_shaped_psbt(wallet_key, spk, leaf, control_block, wallet_key);
        assert_eq!(
            sign_and_count_script_sigs(&mut builder, &psbt),
            Ok(1),
            "a genuine commit-shaped reveal input must still be signed"
        );
    }

    #[test]
    fn script_path_signer_rejects_leaf_not_committed_by_prevout() {
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let wallet_key = wallet_taproot_x_only(&builder);

        // Attacker supplies a valid-looking leaf + control block, but the
        // prevout's scriptPubKey belongs to a completely different taptree.
        // The control block does not commit to it, so nothing may be signed.
        let (_spk, leaf, control_block) = single_leaf_taptree(wallet_key, wallet_key);
        let foreign_key = bitcoin::secp256k1::XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();
        let (foreign_spk, _, _) = single_leaf_taptree(foreign_key, foreign_key);

        let psbt = reveal_shaped_psbt(wallet_key, foreign_spk, leaf, control_block, wallet_key);
        let outcome = sign_and_count_script_sigs(&mut builder, &psbt);
        assert!(
            outcome != Ok(1),
            "a leaf whose control block does not commit to the prevout must never be signed"
        );
        assert!(
            outcome.is_err(),
            "declining every leaf must surface as a refusal, got {outcome:?}"
        );
    }

    #[test]
    fn script_path_signer_rejects_leaf_that_does_not_need_our_key() {
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let wallet_key = wallet_taproot_x_only(&builder);
        let foreign_key = bitcoin::secp256k1::XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();

        // A well-formed taptree rooted at our key, but the leaf requires
        // somebody else's signature. Signing it produces a signature over a
        // script we never inspected; the old code signed every leaf present.
        let (spk, leaf, control_block) = single_leaf_taptree(wallet_key, foreign_key);
        let psbt = reveal_shaped_psbt(wallet_key, spk, leaf, control_block, wallet_key);
        let outcome = sign_and_count_script_sigs(&mut builder, &psbt);
        assert!(
            outcome != Ok(1),
            "a leaf that never pushes our key must not be signed"
        );
        assert!(
            outcome.is_err(),
            "declining every leaf must surface as a refusal, got {outcome:?}"
        );
    }
}

#[cfg(test)]
mod pairing_identity {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder};
    use bdk_wallet::bitcoin::Network;

    /// The pairing identity pubkey is published in cleartext (as
    /// NostrTransportEventV1.pubkey and as `wallet_pubkey_hex` inside
    /// `PairingAckV1` / `SignIntentV1`). It must therefore not be the key whose
    /// BIP-86 tweak produces a funded address, or publishing it hands out the
    /// user's address, balance and full history.
    #[test]
    fn pairing_identity_key_is_not_a_spending_key() {
        let seed = [3u8; 64];
        let wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        let secret_hex = wallet.get_pairing_secret_key_hex().unwrap();
        let pairing_pubkey = crate::sign_intent::pubkey_hex_from_secret_key(&secret_hex).unwrap();

        let taproot_pubkey = wallet.get_taproot_public_key(0).unwrap();
        assert_ne!(
            pairing_pubkey, taproot_pubkey,
            "the published pairing identity must not be the primary spending key"
        );

        // And it must not match any nearby receive index either.
        for index in 0..5 {
            assert_ne!(
                pairing_pubkey,
                wallet.get_taproot_public_key(index).unwrap(),
                "pairing identity collided with taproot receive index {index}"
            );
        }
    }

    /// REGRESSION (fdd60dc — the 2026-07 audit's taproot leaf-signing bypass, the marquee
    /// fund-loss P0): `sign_inscription_script_paths` used to sign EVERY `tap_scripts` leaf,
    /// discarding the control block — a blind script-path oracle reachable from a dapp's
    /// `signPsbt`. The fix binds each leaf to the prevout: the control block must commit to
    /// the prevout's taproot output key. Here a reveal-shaped leaf (pushes our key + carries
    /// an `ord` envelope, internal key = ours, so the push/ownership gates pass) is paired
    /// with a prevout whose P2TR output key is DIFFERENT from the one the control block
    /// commits to, so the commitment check must reject it — no `tap_script_sig`.
    #[test]
    fn sign_inscription_refuses_a_leaf_the_prevout_does_not_commit_to() {
        use crate::builder::SignOptions;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::blockdata::script::Builder;
        use bitcoin::hashes::Hash as _;
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
        use bitcoin::opcodes::OP_FALSE;
        use bitcoin::psbt::Psbt;
        use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{
            Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        use std::str::FromStr as _;

        let secp = Secp256k1::new();
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let reveal_xonly =
            XOnlyPublicKey::from_str(&wallet.get_taproot_public_key(0).unwrap()).unwrap();

        // Reveal-shaped leaf: <our key> OP_CHECKSIG  OP_FALSE OP_IF "ord" OP_ENDIF — passes the
        // "pushes our key" gate and the "looks like a reveal" ownership gate.
        let leaf = Builder::new()
            .push_x_only_key(&reveal_xonly)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"ord")
            .push_opcode(OP_ENDIF)
            .into_script();

        // The control block is built for THIS taptree (output key K1)...
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, reveal_xonly)
            .unwrap();
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();

        // ...but the prevout is a DIFFERENT, NON-WALLET taproot output (key-path spend of an
        // unrelated key, K2 != K1), so the control block does not commit to it. It must be a
        // key we do NOT own, or the wallet would simply key-path sign it and the reveal signer
        // would skip it as already-signed — masking the gate we mean to exercise.
        let foreign_xonly = XOnlyPublicKey::from_str(
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", // BIP-340 vector
        )
        .unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, foreign_xonly, None),
        };

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, reveal_xonly, None),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevout);
        // Reveal selector: our key + the empty [0,0,0,0] origin fingerprint the signer keys off.
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_key_origins.insert(
            reveal_xonly,
            (
                vec![leaf_hash],
                (Fingerprint::from([0u8; 4]), DerivationPath::master()),
            ),
        );
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf.clone(), LeafVersion::TapScript));

        let b64 = STANDARD.encode(psbt.serialize());
        let signed_b64 = wallet
            .sign_psbt(
                &b64,
                Some(SignOptions {
                    sign_inputs: None,
                    sighash: None,
                    finalize: false,
                }),
            )
            .expect("sign_psbt returns Ok (refusing the leaf, not erroring)");
        let signed = Psbt::deserialize(&STANDARD.decode(signed_b64).unwrap()).unwrap();

        assert!(
            signed.inputs[0].tap_script_sigs.is_empty(),
            "signer must refuse a script-path leaf whose control block does not commit to the \
             prevout's taproot output key (blind-signing oracle); got {} sig(s)",
            signed.inputs[0].tap_script_sigs.len()
        );
    }
}
