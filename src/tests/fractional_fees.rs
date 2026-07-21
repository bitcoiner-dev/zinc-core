//! Sub-sat / fractional fee-rate coverage: the `fee_rate_from_sat_per_vb_f64` and
//! `fee_for_vsize` helpers, fractional rates flowing through `CreatePsbtRequest`
//! and the consolidate planner, and the never-underpay invariant.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{
        fee_for_vsize, fee_rate_from_sat_per_vb_f64, AddressScheme, CreatePsbtRequest, Seed64,
        WalletBuilder, ZincWallet,
    };
    use crate::error::ZincError;
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Address, Amount, BlockHash, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;

    #[test]
    fn helper_converts_fractional_rates_to_kwu_precision() {
        for (rate, expected_kwu) in [
            (0.1, 25),
            (0.5, 125),
            (0.9, 225),
            (1.0, 250),
            (1.5, 375),
            // 0.123 * 250 = 30.75 → ceil to 31 (round up, never underpay)
            (0.123, 31),
        ] {
            let fee_rate = fee_rate_from_sat_per_vb_f64(rate).unwrap();
            assert_eq!(
                fee_rate.to_sat_per_kwu(),
                expected_kwu,
                "{rate} sat/vB should map to {expected_kwu} sat/kwu"
            );
        }
    }

    #[test]
    fn helper_rejects_invalid_rates() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 200_000.0] {
            match fee_rate_from_sat_per_vb_f64(bad) {
                Err(ZincError::ConfigError(m)) => {
                    assert!(m.contains("Invalid fee rate"), "unexpected message: {m}");
                }
                other => panic!("expected ConfigError for rate {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn fee_for_vsize_rounds_up_without_rerounding_the_rate() {
        for (rate, vsize, expected_fee) in [
            (0.5, 200, 100),  // exact: 200 * 0.5
            (0.5, 141, 71),   // 70.5 → ceil
            (1.5, 100, 150),  // fractional above 1 sat/vB
            (0.1, 1000, 100), // deep sub-sat
            (0.1, 7, 1),      // 0.7 → ceil, still nonzero
        ] {
            let fee_rate = fee_rate_from_sat_per_vb_f64(rate).unwrap();
            assert_eq!(
                fee_for_vsize(fee_rate, vsize),
                expected_fee,
                "fee for {vsize} vB at {rate} sat/vB"
            );
        }
    }

    #[test]
    fn create_psbt_request_accepts_fractional_rates() {
        let recipient = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let request = CreatePsbtRequest::from_parts(recipient, 10_000, 0.5).unwrap();
        assert_eq!(request.fee_rate.to_sat_per_kwu(), 125);
        let request = CreatePsbtRequest::from_parts(recipient, 10_000, 1.5).unwrap();
        assert_eq!(request.fee_rate.to_sat_per_kwu(), 375);
        assert!(CreatePsbtRequest::from_parts(recipient, 10_000, 0.0).is_err());
    }

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

    fn consolidate_fee_at(rate: f64) -> (u64, usize) {
        let (mut w, addr, ops) = funded_wallet(&[40_000, 60_000]);
        w.ordinals_verified = true;
        let op_strs: Vec<String> = ops.iter().map(ToString::to_string).collect();
        let b64 = w
            .plan_consolidate_base64(&op_strs, rate, &addr.to_string())
            .unwrap_or_else(|e| panic!("consolidate at {rate} sat/vB: {e}"));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let psbt = Psbt::deserialize(&bytes).unwrap();
        let total_in: u64 = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.as_ref().unwrap().value.to_sat())
            .sum();
        let total_out: u64 = psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        (total_in - total_out, psbt.unsigned_tx.vsize())
    }

    // The planner budgets fees against a signed-size estimate, so the paid fee must
    // never fall below `ceil(unsigned_vsize * rate)` (never underpay) and fractional
    // rates must actually change the fee (no silent re-rounding to whole sat/vB).
    #[test]
    fn consolidate_at_fractional_rates_never_underpays() {
        let mut previous_fee = 0u64;
        for rate in [0.1, 0.5, 0.9, 1.5] {
            let (fee, unsigned_vsize) = consolidate_fee_at(rate);
            let floor = (unsigned_vsize as f64 * rate).ceil() as u64;
            assert!(
                fee >= floor,
                "at {rate} sat/vB fee {fee} underpays floor {floor} (vsize {unsigned_vsize})"
            );
            assert!(
                fee > previous_fee,
                "fee must grow with the rate: {fee} !> {previous_fee} at {rate} sat/vB"
            );
            previous_fee = fee;
        }

        // Sub-sat must be materially cheaper than 1 sat/vB — the old integer path
        // would have ceiled 0.5 up to 1 and paid the same fee.
        let (fee_half, _) = consolidate_fee_at(0.5);
        let (fee_one, _) = consolidate_fee_at(1.0);
        assert!(
            fee_half < fee_one,
            "0.5 sat/vB ({fee_half}) should pay less than 1 sat/vB ({fee_one})"
        );
    }
}
