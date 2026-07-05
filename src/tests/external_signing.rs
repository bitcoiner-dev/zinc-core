//! Branch coverage for the hardware/external-signing surface of `builder.rs`:
//! `prepare_external_sign_psbt` (enrichment, sign-index bounds/dup, sighash policy) and
//! `verify_external_signed_psbt` (tx immutability, required-signed, unauthorized-signature
//! rejection, finalize). These mirror the `witness_utxo`-only signable-PSBT pattern used by
//! `signing.rs`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, SignOptions, WalletBuilder, ZincWallet};
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;
    use bitcoin::psbt::Psbt;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn dummy_tx(value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid;
        let txid = Txid::from_byte_array(hash_bytes);
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    /// Funded wallet + an unsigned single-input PSBT (base64) spending that UTXO back to the
    /// wallet, with `witness_utxo` populated so BDK can sign it.
    fn setup() -> (ZincWallet, String) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let addr = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        let prev = dummy_tx(50_000, script.clone(), 1);
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_tx(prev.clone());
        let _ = graph.insert_anchor(
            prev.compute_txid(),
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 100,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 1000,
            },
        );
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

        let unsigned = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(prev.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(prev.output[0].clone());
        (wallet, b64(&psbt.serialize()))
    }

    fn sign_all(wallet: &mut ZincWallet, unsigned_b64: &str) -> String {
        wallet
            .sign_psbt(
                unsigned_b64,
                Some(SignOptions {
                    sign_inputs: None,
                    sighash: None,
                    finalize: false,
                }),
            )
            .expect("sign")
    }

    fn decode(b64_str: &str) -> Psbt {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64_str)
            .unwrap();
        Psbt::deserialize(&raw).unwrap()
    }

    // ---------- prepare_external_sign_psbt ----------

    #[test]
    fn prepare_external_rejects_invalid_base64() {
        let (w, _) = setup();
        let err = w
            .prepare_external_sign_psbt("!!!not base64!!!", None)
            .unwrap_err();
        assert!(err.contains("Invalid base64"), "{err}");
    }

    #[test]
    fn prepare_external_rejects_invalid_psbt() {
        let (w, _) = setup();
        let err = w
            .prepare_external_sign_psbt(&b64(&[1, 2, 3, 4]), None)
            .unwrap_err();
        assert!(err.contains("Invalid PSBT"), "{err}");
    }

    #[test]
    fn prepare_external_rejects_out_of_bounds_sign_index() {
        let (w, unsigned) = setup();
        let opts = SignOptions {
            sign_inputs: Some(vec![5]),
            sighash: None,
            finalize: false,
        };
        let err = w
            .prepare_external_sign_psbt(&unsigned, Some(opts))
            .unwrap_err();
        assert!(err.contains("out of bounds"), "{err}");
    }

    #[test]
    fn prepare_external_rejects_duplicate_sign_index() {
        let (w, unsigned) = setup();
        let opts = SignOptions {
            sign_inputs: Some(vec![0, 0]),
            sighash: None,
            finalize: false,
        };
        let err = w
            .prepare_external_sign_psbt(&unsigned, Some(opts))
            .unwrap_err();
        assert!(err.contains("duplicated"), "{err}");
    }

    #[test]
    fn prepare_external_rejects_disallowed_sighash() {
        let (w, unsigned) = setup();
        // 0x83 = SIGHASH_SINGLE | ANYONECANPAY — disallowed.
        let opts = SignOptions {
            sign_inputs: None,
            sighash: Some(0x83),
            finalize: false,
        };
        let err = w
            .prepare_external_sign_psbt(&unsigned, Some(opts))
            .unwrap_err();
        assert!(err.contains("Sighash type is not allowed"), "{err}");
    }

    #[test]
    fn prepare_external_enriches_missing_witness_utxo() {
        let (w, unsigned) = setup();
        // Strip witness_utxo: preparation must re-enrich it from the wallet's own UTXOs.
        let mut psbt = decode(&unsigned);
        psbt.inputs[0].witness_utxo = None;
        let stripped = b64(&psbt.serialize());

        let prepared = w
            .prepare_external_sign_psbt(&stripped, None)
            .expect("prepare");
        let out = decode(&prepared);
        assert!(
            out.inputs[0].witness_utxo.is_some(),
            "enrichment should restore witness_utxo from wallet UTXOs"
        );
    }

    // ---------- verify_external_signed_psbt ----------

    #[test]
    fn verify_rejects_invalid_base64_original() {
        let (w, signed) = {
            let (mut w, unsigned) = setup();
            let s = sign_all(&mut w, &unsigned);
            (w, s)
        };
        let err = w
            .verify_external_signed_psbt("@@@", &signed, None, false)
            .unwrap_err();
        assert!(err.contains("Invalid base64 in original"), "{err}");
    }

    #[test]
    fn verify_rejects_modified_unsigned_tx() {
        let (w, unsigned) = setup();
        // A different PSBT (different output value) masquerading as the "signed" result.
        let (_w2, other) = setup_with_output(48_000);
        let err = w
            .verify_external_signed_psbt(&unsigned, &other, None, false)
            .unwrap_err();
        assert!(err.contains("modified transaction"), "{err}");
    }

    #[test]
    fn verify_rejects_required_input_not_signed() {
        let (w, unsigned) = setup();
        // "signed" == unsigned: required input 0 has no signature.
        let err = w
            .verify_external_signed_psbt(&unsigned, &unsigned, Some(&[0]), false)
            .unwrap_err();
        assert!(err.contains("was not signed by the device"), "{err}");
    }

    #[test]
    fn verify_rejects_unauthorized_signature() {
        let (mut w, unsigned) = setup();
        let signed = sign_all(&mut w, &unsigned);
        // required set is empty, yet input 0 carries a signature → unauthorized.
        let err = w
            .verify_external_signed_psbt(&unsigned, &signed, Some(&[]), false)
            .unwrap_err();
        assert!(err.contains("unauthorized signature"), "{err}");
    }

    #[test]
    fn verify_accepts_properly_signed_psbt() {
        let (mut w, unsigned) = setup();
        let signed = sign_all(&mut w, &unsigned);
        let out = w
            .verify_external_signed_psbt(&unsigned, &signed, None, false)
            .expect("verify");
        // Signature preserved; derivation metadata stripped for multi-pass safety.
        let psbt = decode(&out);
        assert!(psbt.inputs[0].tap_key_sig.is_some());
        assert!(psbt.inputs[0].tap_key_origins.is_empty());
    }

    #[test]
    fn verify_finalizes_into_witness() {
        let (mut w, unsigned) = setup();
        let signed = sign_all(&mut w, &unsigned);
        let out = w
            .verify_external_signed_psbt(&unsigned, &signed, None, true)
            .expect("verify+finalize");
        let psbt = decode(&out);
        assert!(
            psbt.inputs[0].final_script_witness.is_some(),
            "finalize must move tap_key_sig into the final witness"
        );
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    /// Variant of `setup` whose unsigned PSBT pays a different amount, to force a tx mismatch.
    fn setup_with_output(value: u64) -> (ZincWallet, String) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let addr = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();
        let prev = dummy_tx(50_000, script.clone(), 1);
        let unsigned = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(prev.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(prev.output[0].clone());
        (wallet, b64(&psbt.serialize()))
    }
}
