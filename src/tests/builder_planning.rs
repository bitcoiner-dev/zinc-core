//! Negative + edge-case coverage for the unsigned transaction planners in `builder.rs`:
//! `plan_salvage_tx`, `plan_consolidate_tx`, `plan_send_with_salvage_tx`, and their
//! string/base64 wrappers. The happy paths live in `utxo_list.rs`; these exercise the
//! safety gates (ordinals verification, dust, insufficient funds, protected/unknown UTXOs,
//! zero amount) and the wrapper parse errors.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder, ZincWallet};
    use crate::error::ZincError;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Address, Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;

    fn dummy_tx(value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid;
        let txid = Txid::from_byte_array(hash_bytes);
        let input = bdk_wallet::bitcoin::TxIn {
            previous_output: OutPoint::new(txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bdk_wallet::bitcoin::Witness::default(),
        };
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    /// Build a Regtest unified-scheme wallet funded with one confirmed UTXO per entry in
    /// `values`. Returns the wallet, its receive address, and the outpoints (in `values` order).
    fn funded_wallet(values: &[u64]) -> (ZincWallet, Address, Vec<OutPoint>) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let addr = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let spk = addr.script_pubkey();

        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let hash = BlockHash::all_zeros();
        let mut ops = Vec::new();
        for (i, &v) in values.iter().enumerate() {
            let tx = dummy_tx(v, spk.clone(), u8::try_from(i).unwrap() + 1);
            let _ = graph.insert_tx(tx.clone());
            let _ = graph.insert_anchor(
                tx.compute_txid(),
                ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 100 + u32::try_from(i).unwrap(),
                        hash,
                    },
                    confirmation_time: 1000 + u64::try_from(i).unwrap(),
                },
            );
            ops.push(OutPoint::new(tx.compute_txid(), 0));
        }
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 0);
        wallet
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last,
            })
            .unwrap();
        (wallet, addr, ops)
    }

    fn fee1() -> FeeRate {
        FeeRate::from_sat_per_vb(1).unwrap()
    }

    fn foreign_outpoint(uid: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([uid; 32]), 0)
    }

    fn wallet_err(r: Result<impl std::fmt::Debug, ZincError>, needle: &str) {
        match r {
            Err(ZincError::WalletError(m)) => assert!(
                m.contains(needle),
                "expected WalletError containing {needle:?}, got: {m}"
            ),
            other => panic!("expected WalletError({needle:?}), got {other:?}"),
        }
    }

    fn config_err(r: Result<impl std::fmt::Debug, ZincError>, needle: &str) {
        match r {
            Err(ZincError::ConfigError(m)) => assert!(
                m.contains(needle),
                "expected ConfigError containing {needle:?}, got: {m}"
            ),
            other => panic!("expected ConfigError({needle:?}), got {other:?}"),
        }
    }

    // ---------- plan_salvage_tx ----------

    #[test]
    fn salvage_requires_ordinals_verified() {
        // Defaults to ordinals_verified = false: the safety lock must engage.
        let (w, addr, ops) = funded_wallet(&[10_000]);
        wallet_err(
            w.plan_salvage_tx(&ops, fee1(), 546, &addr, &addr),
            "safety lock",
        );
    }

    #[test]
    fn salvage_rejects_empty_outpoints() {
        let (mut w, addr, _) = funded_wallet(&[10_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_salvage_tx(&[], fee1(), 546, &addr, &addr),
            "No UTXOs selected",
        );
    }

    #[test]
    fn salvage_rejects_unknown_utxo() {
        let (mut w, addr, _) = funded_wallet(&[10_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_salvage_tx(&[foreign_outpoint(0xAA)], fee1(), 546, &addr, &addr),
            "not found in wallet",
        );
    }

    #[test]
    fn salvage_rejects_insufficient_funds() {
        // 600 sat input: only 54 cardinal sats above the 546 postage — below dust, so nothing is
        // recoverable and the build is refused.
        let (mut w, addr, ops) = funded_wallet(&[600]);
        w.ordinals_verified = true;
        w.inscribed_utxos.insert(ops[0]);
        wallet_err(
            w.plan_salvage_tx(&ops, fee1(), 546, &addr, &addr),
            "no cardinal sats above the dust threshold",
        );
    }

    // ---------- plan_consolidate_tx ----------

    #[test]
    fn consolidate_rejects_empty_outpoints() {
        let (w, addr, _) = funded_wallet(&[40_000]);
        wallet_err(
            w.plan_consolidate_tx(&[], fee1(), &addr),
            "No UTXOs selected for consolidation",
        );
    }

    #[test]
    fn consolidate_rejects_unknown_utxo() {
        let (w, addr, _) = funded_wallet(&[40_000]);
        wallet_err(
            w.plan_consolidate_tx(&[foreign_outpoint(0xBB)], fee1(), &addr),
            "not found in wallet",
        );
    }

    #[test]
    fn consolidate_rejects_dust_after_fee() {
        // 600 sat - fee lands below the 546 dust floor → rejected.
        let (w, addr, ops) = funded_wallet(&[600]);
        wallet_err(
            w.plan_consolidate_tx(&ops, fee1(), &addr),
            "Insufficient funds for consolidation",
        );
    }

    // ---------- plan_send_with_salvage_tx ----------

    #[test]
    fn send_requires_ordinals_verified() {
        let (w, addr, ops) = funded_wallet(&[50_000]);
        wallet_err(
            w.plan_send_with_salvage_tx(&ops, &addr, 1_000, fee1(), 546, &addr, &addr),
            "safety lock",
        );
    }

    #[test]
    fn send_rejects_empty_inputs() {
        let (mut w, addr, _) = funded_wallet(&[50_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_send_with_salvage_tx(&[], &addr, 1_000, fee1(), 546, &addr, &addr),
            "No inputs provided",
        );
    }

    #[test]
    fn send_rejects_zero_amount() {
        let (mut w, addr, ops) = funded_wallet(&[50_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_send_with_salvage_tx(&ops, &addr, 0, fee1(), 546, &addr, &addr),
            "greater than zero",
        );
    }

    #[test]
    fn send_rejects_unknown_utxo() {
        let (mut w, addr, _) = funded_wallet(&[50_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_send_with_salvage_tx(&[foreign_outpoint(0xCC)], &addr, 1_000, fee1(), 546, &addr, &addr),
            "not found in wallet",
        );
    }

    #[test]
    fn send_rejects_insufficient_funds() {
        let (mut w, addr, ops) = funded_wallet(&[2_000]);
        w.ordinals_verified = true;
        wallet_err(
            w.plan_send_with_salvage_tx(&ops, &addr, 5_000, fee1(), 546, &addr, &addr),
            "Insufficient funds",
        );
    }

    #[test]
    fn send_absorbs_dust_change_into_fee() {
        // Clean send leaving < 546 leftover: the change output is dropped (absorbed into fee),
        // so only the recipient output remains.
        let (mut w, addr, ops) = funded_wallet(&[10_000]);
        w.ordinals_verified = true;
        let psbt = w
            .plan_send_with_salvage_tx(&ops, &addr, 9_700, fee1(), 546, &addr, &addr)
            .expect("send psbt");
        assert_eq!(
            psbt.unsigned_tx.output.len(),
            1,
            "dust change must be absorbed, leaving only the recipient output"
        );
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 9_700);
    }

    // ---------- base64 wrapper parse errors (plan_consolidate_base64) ----------

    #[test]
    fn consolidate_base64_rejects_overflowing_fee_rate() {
        // `FeeRate::from_sat_per_vb` only returns None on overflow (0 is a valid rate),
        // so an absurd sat/vB is what trips the "Invalid fee rate" guard.
        let (w, _, _) = funded_wallet(&[40_000]);
        config_err(
            w.plan_consolidate_base64(&[], u64::MAX, "ignored"),
            "Invalid fee rate",
        );
    }

    #[test]
    fn consolidate_base64_rejects_bad_address() {
        let (w, _, _) = funded_wallet(&[40_000]);
        config_err(
            w.plan_consolidate_base64(&[], 1, "not-an-address"),
            "Invalid destination address",
        );
    }

    #[test]
    fn consolidate_base64_rejects_wrong_network_address() {
        // Regtest wallet, but a valid mainnet address → network mismatch.
        let (w, _, _) = funded_wallet(&[40_000]);
        config_err(
            w.plan_consolidate_base64(&[], 1, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            "network mismatch",
        );
    }

    #[test]
    fn consolidate_base64_rejects_bad_outpoint() {
        let (w, addr, _) = funded_wallet(&[40_000]);
        let dest = addr.to_string();
        config_err(
            w.plan_consolidate_base64(&["not-an-outpoint".to_string()], 1, &dest),
            "Invalid outpoint",
        );
    }

    #[test]
    fn consolidate_base64_happy_path_round_trips_through_strings() {
        use base64::Engine;
        let (w, addr, ops) = funded_wallet(&[40_000, 60_000]);
        let dest = addr.to_string();
        let op_strs: Vec<String> = ops.iter().map(ToString::to_string).collect();
        let b64 = w
            .plan_consolidate_base64(&op_strs, 1, &dest)
            .expect("consolidate base64");
        // The wrapper returns a STANDARD-base64 PSBT spending both inputs into one output.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .expect("valid base64");
        let psbt = bdk_wallet::bitcoin::Psbt::deserialize(&raw).expect("valid psbt");
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.inputs.len(), 2);
    }
}
