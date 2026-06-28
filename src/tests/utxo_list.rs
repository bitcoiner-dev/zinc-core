#[cfg(test)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder};
    use crate::ordinals::types::{Inscription, Satpoint};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut};
    use bdk_wallet::chain::ConfirmationBlockTime;
    use bdk_wallet::KeychainKind;

    fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid;
        let dummy_txid = bdk_wallet::bitcoin::Txid::from_byte_array(hash_bytes);
        let dummy_input = bdk_wallet::bitcoin::TxIn {
            previous_output: OutPoint::new(dummy_txid, 0),
            script_sig: ScriptBuf::new(),
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

    // Verifies list_utxos() annotates each UTXO with ordinal info: protected outpoints flip
    // is_inscribed; inscription-bearing UTXOs expose matched ids/offsets + salvageable cardinal sats
    // (value - 546 per inscription); clean BTC UTXOs report nothing salvageable.
    #[test]
    fn test_list_utxos_ordinal_awareness() {
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
        let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let anchor = |graph: &mut bdk_wallet::chain::TxGraph<ConfirmationBlockTime>,
                      tx: &Transaction,
                      height: u32| {
            let _ = graph.insert_tx(tx.clone());
            let _ = graph.insert_anchor(
                tx.compute_txid(),
                ConfirmationBlockTime {
                    block_id: bdk_wallet::chain::BlockId {
                        height,
                        hash: dummy_block_hash,
                    },
                    confirmation_time: 1000 + u64::from(height),
                },
            );
        };

        // rune-only protected (no inscription metadata), inscription-bearing, and clean BTC
        let tx_rune = create_dummy_tx(330, script.clone(), 1);
        let tx_insc = create_dummy_tx(10_000, script.clone(), 2);
        let tx_btc = create_dummy_tx(314_000_000, script.clone(), 3);
        anchor(&mut graph, &tx_rune, 100);
        anchor(&mut graph, &tx_insc, 101);
        anchor(&mut graph, &tx_btc, 102);

        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 1);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last_active,
            })
            .unwrap();

        let op_rune = OutPoint::new(tx_rune.compute_txid(), 0);
        let op_insc = OutPoint::new(tx_insc.compute_txid(), 0);
        let op_btc = OutPoint::new(tx_btc.compute_txid(), 0);

        // Both protected outpoints in the shield set; only op_insc has inscription metadata.
        builder.inscribed_utxos.insert(op_rune);
        builder.inscribed_utxos.insert(op_insc);
        builder.inscriptions.push(Inscription {
            id: "insc-1".to_string(),
            number: 1,
            satpoint: Satpoint {
                outpoint: op_insc,
                offset: 0,
            },
            content_type: Some("image/png".to_string()),
            value: Some(10_000),
            content_length: None,
            timestamp: None,
        });

        let utxos = builder.list_utxos();
        assert!(utxos.len() >= 3, "expected at least 3 utxos");

        let find = |op: OutPoint| {
            utxos
                .iter()
                .find(|u| u.txid == op.txid.to_string() && u.vout == op.vout)
                .unwrap_or_else(|| panic!("missing utxo {op:?}"))
        };

        let rune = find(op_rune);
        assert!(rune.is_inscribed, "rune utxo should be protected");
        assert!(!rune.has_inscription, "rune utxo has no inscription metadata");
        assert_eq!(rune.cardinal_salvageable_sats, 0, "no salvage without inscription metadata");

        let insc = find(op_insc);
        assert!(insc.is_inscribed && insc.has_inscription);
        assert_eq!(insc.inscription_ids, vec!["insc-1".to_string()]);
        assert_eq!(insc.inscription_offsets, vec![0]);
        assert_eq!(
            insc.cardinal_salvageable_sats, 10_000 - 546,
            "salvageable = value minus one padding"
        );

        let btc = find(op_btc);
        assert!(!btc.is_inscribed && !btc.has_inscription);
        assert_eq!(btc.cardinal_salvageable_sats, 0);
        assert_eq!(btc.value_sats, 314_000_000);
        assert!(btc.address.is_some(), "address should resolve from keychain");
        assert_eq!(btc.wallet_role, "taproot");
    }

    // Regression for the ordinal-safety bug: the ordinals-protection scan must cover USED addresses
    // (which hold UTXOs/inscriptions), not just index 0 + unused gap addresses. A UTXO on a higher
    // index must appear in collect_active_addresses() so its inscriptions get detected and excluded
    // from sends.
    #[test]
    fn test_collect_active_addresses_includes_used_addresses() {
        let seed = [0u8; 64];
        let mut builder = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();

        // Reveal a few addresses and fund index 2 (a USED, non-zero index).
        let _ = builder.vault_wallet.reveal_next_address(KeychainKind::External);
        let _ = builder.vault_wallet.reveal_next_address(KeychainKind::External);
        let addr2 = builder.vault_wallet.peek_address(KeychainKind::External, 2).address;

        let mut graph = bdk_wallet::chain::TxGraph::default();
        let tx = create_dummy_tx(50_000, addr2.script_pubkey(), 7);
        let _ = graph.insert_tx(tx.clone());
        let _ = graph.insert_anchor(
            tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: bdk_wallet::bitcoin::BlockHash::all_zeros(),
                },
                confirmation_time: 1000,
            },
        );
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 2);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last,
            })
            .unwrap();

        let active = builder.collect_active_addresses();
        assert!(
            active.contains(&addr2.to_string()),
            "ordinals scan must include the used address holding a UTXO (index 2); got {active:?}"
        );
    }

    // plan_send_with_salvage_tx pays a recipient while auto-salvaging an inscription UTXO: the inscribed
    // input is ordered first with its own padded output first (recipient + change follow).
    #[test]
    fn test_plan_send_with_salvage_funds_from_inscription() {
        use bdk_wallet::bitcoin::FeeRate;

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
        let hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let insc_tx = create_dummy_tx(10_000, script.clone(), 1);
        let clean_tx = create_dummy_tx(40_000, script.clone(), 2);
        for (tx, h) in [(&insc_tx, 100u32), (&clean_tx, 101u32)] {
            let _ = graph.insert_tx(tx.clone());
            let _ = graph.insert_anchor(
                tx.compute_txid(),
                ConfirmationBlockTime {
                    block_id: bdk_wallet::chain::BlockId { height: h, hash },
                    confirmation_time: 1000 + u64::from(h),
                },
            );
        }
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 0);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last,
            })
            .unwrap();

        let insc_op = OutPoint::new(insc_tx.compute_txid(), 0);
        let clean_op = OutPoint::new(clean_tx.compute_txid(), 0);
        builder.inscribed_utxos.insert(insc_op);
        builder.ordinals_verified = true;

        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        // Pass inputs clean-first to prove the builder reorders the inscribed input to the front.
        let psbt = builder
            .plan_send_with_salvage_tx(&[clean_op, insc_op], &addr, 45_000, fee_rate, 546, &addr, &addr)
            .expect("smart-send psbt");

        assert_eq!(
            psbt.unsigned_tx.input[0].previous_output, insc_op,
            "inscribed input must be first"
        );
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 546, "inscription postage output first");
        assert_eq!(psbt.unsigned_tx.output[1].value.to_sat(), 45_000, "recipient output");
        assert!(psbt.unsigned_tx.output.len() >= 2);
        assert!(psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));
    }

    // plan_consolidate_tx sweeps clean UTXOs into one output and refuses protected ones.
    #[test]
    fn test_plan_consolidate_clean_utxos() {
        use bdk_wallet::bitcoin::FeeRate;

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
        let hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
        let tx1 = create_dummy_tx(40_000, script.clone(), 1);
        let tx2 = create_dummy_tx(60_000, script.clone(), 2);
        for (tx, h) in [(&tx1, 100u32), (&tx2, 101u32)] {
            let _ = graph.insert_tx(tx.clone());
            let _ = graph.insert_anchor(
                tx.compute_txid(),
                ConfirmationBlockTime {
                    block_id: bdk_wallet::chain::BlockId { height: h, hash },
                    confirmation_time: 1000 + u64::from(h),
                },
            );
        }
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 0);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last,
            })
            .unwrap();

        let op1 = OutPoint::new(tx1.compute_txid(), 0);
        let op2 = OutPoint::new(tx2.compute_txid(), 0);
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

        let psbt = builder
            .plan_consolidate_tx(&[op1, op2], fee_rate, &addr)
            .expect("consolidate psbt");
        assert_eq!(psbt.unsigned_tx.output.len(), 1, "single consolidated output");
        let out = psbt.unsigned_tx.output[0].value.to_sat();
        assert!(out > 0 && out < 100_000, "output = total - fee, got {out}");
        assert!(psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));

        // Protected UTXO must be refused.
        builder.inscribed_utxos.insert(op2);
        assert!(
            builder.plan_consolidate_tx(&[op1, op2], fee_rate, &addr).is_err(),
            "must refuse a protected UTXO"
        );
    }

    // plan_salvage_tx builds a strip-postage PSBT: a 10k-sat inscription UTXO → one 546-sat postage
    // output (the inscription) + one recovery output (cardinal sats minus fee), with witness_utxo set.
    #[test]
    fn test_plan_salvage_recovers_cardinal_sats() {
        use bdk_wallet::bitcoin::FeeRate;

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
        let tx = create_dummy_tx(10_000, script.clone(), 1);
        let _ = graph.insert_tx(tx.clone());
        let _ = graph.insert_anchor(
            tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: bdk_wallet::chain::BlockId {
                    height: 100,
                    hash: bdk_wallet::bitcoin::BlockHash::all_zeros(),
                },
                confirmation_time: 1000,
            },
        );
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 0);
        builder
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last,
            })
            .unwrap();

        let op = OutPoint::new(tx.compute_txid(), 0);
        builder.inscribed_utxos.insert(op);
        builder.ordinals_verified = true;

        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let psbt = builder
            .plan_salvage_tx(&[op], fee_rate, 546, &addr, &addr)
            .expect("salvage psbt");

        assert_eq!(
            psbt.unsigned_tx.output.len(),
            2,
            "one postage output + one recovery output"
        );
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 546);
        let recovered = psbt.unsigned_tx.output[1].value.to_sat();
        assert!(
            recovered > 0 && recovered < 10_000 - 546,
            "recovered = value - postage - fee, got {recovered}"
        );
        assert!(
            psbt.inputs[0].witness_utxo.is_some(),
            "witness_utxo populated for signing"
        );
    }
}
