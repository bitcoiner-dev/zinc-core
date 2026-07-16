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

    // ---- enrich_psbt_key_origins ----

    #[test]
    fn enrich_adds_taproot_key_origins_to_planner_shaped_psbt() {
        // setup()'s PSBT is planner-shaped: witness_utxo only, no key origins.
        let (wallet, unsigned) = setup();
        let before = decode(&unsigned);
        assert!(before.inputs[0].tap_internal_key.is_none());
        assert!(before.inputs[0].tap_key_origins.is_empty());

        let enriched = wallet.enrich_psbt_key_origins(&unsigned).expect("enrich");
        let psbt = decode(&enriched);
        assert!(
            psbt.inputs[0].tap_internal_key.is_some(),
            "taproot input must gain an internal key"
        );
        assert!(
            !psbt.inputs[0].tap_key_origins.is_empty(),
            "taproot input must gain a key origin (device fingerprint + path)"
        );
        // Unsigned tx is untouched — enrichment only annotates.
        assert_eq!(psbt.unsigned_tx, before.unsigned_tx);
    }

    #[test]
    fn enrich_is_idempotent() {
        let (wallet, unsigned) = setup();
        let once = wallet.enrich_psbt_key_origins(&unsigned).expect("enrich");
        let twice = wallet.enrich_psbt_key_origins(&once).expect("re-enrich");
        // Re-running over an already-enriched PSBT yields the same origins.
        let a = decode(&once);
        let b = decode(&twice);
        assert_eq!(a.inputs[0].tap_internal_key, b.inputs[0].tap_internal_key);
        assert_eq!(a.inputs[0].tap_key_origins, b.inputs[0].tap_key_origins);
    }

    #[test]
    fn enrich_leaves_foreign_input_untouched() {
        let (wallet, _) = setup();
        // A PSBT spending an outpoint the wallet does not own, with a foreign spk.
        let foreign_prev = dummy_tx(10_000, ScriptBuf::from_bytes(vec![0x51, 0x01, 0x01]), 9);
        let unsigned = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(foreign_prev.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: foreign_prev.output[0].script_pubkey.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(foreign_prev.output[0].clone());
        let enriched = wallet
            .enrich_psbt_key_origins(&b64(&psbt.serialize()))
            .expect("enrich");
        let out = decode(&enriched);
        assert!(out.inputs[0].tap_internal_key.is_none());
        assert!(out.inputs[0].tap_key_origins.is_empty());
    }

    #[test]
    fn enrich_rejects_garbage() {
        let (wallet, _) = setup();
        assert!(wallet.enrich_psbt_key_origins("not base64!!!").is_err());
        assert!(wallet.enrich_psbt_key_origins(&b64(b"not a psbt")).is_err());
    }

    /// After enrichment a hardware-shaped (planner) PSBT is signable by the seed wallet —
    /// proves the metadata is coherent end to end.
    #[test]
    fn enriched_psbt_is_signable() {
        let (mut wallet, unsigned) = setup();
        let enriched = wallet.enrich_psbt_key_origins(&unsigned).expect("enrich");
        let signed = sign_all(&mut wallet, &enriched);
        let psbt = decode(&signed);
        assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "enriched taproot input must be signable"
        );
    }

    /// Accessors for hosts that orchestrate ordinals syncs outside the wallet
    /// lock: tip height for the indexer-lag check, and the fail-closed
    /// unverified marker.
    #[test]
    fn host_ordinals_orchestration_accessors() {
        let (mut wallet, _) = setup();
        // setup() applies tx anchors but never extends the local chain.
        assert_eq!(wallet.chain_tip_height(), 0);

        wallet.apply_verified_ordinals_update(
            Vec::new(),
            std::collections::HashSet::new(),
            Vec::new(),
        );
        assert!(wallet.ordinals_verified());
        wallet.mark_ordinals_unverified();
        assert!(!wallet.ordinals_verified());
    }
}
