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
        setup_with_values(50_000, 49_000)
    }

    fn setup_with_values(input_value: u64, output_value: u64) -> (ZincWallet, String) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let addr = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let script = addr.script_pubkey();

        let prev = dummy_tx(input_value, script.clone(), 1);
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
        wallet.mark_current_wallet_outpoints_classified_for_test();

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
                value: Amount::from_sat(output_value),
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

    #[test]
    fn rejects_unknown_owned_outpoints_on_both_signing_boundaries() {
        use bdk_wallet::miniscript::psbt::PsbtExt;
        for index in [0, 100_000] {
            for selected in [None, Some(vec![0])] {
                let (mut wallet, encoded) = setup();
                let mut psbt = decode(&encoded);
                let descriptor = wallet
                    .vault_wallet
                    .public_descriptor(KeychainKind::External)
                    .at_derivation_index(index)
                    .unwrap();
                let script = descriptor
                    .derived_descriptor(wallet.vault_wallet.secp_ctx())
                    .unwrap()
                    .script_pubkey();
                psbt.unsigned_tx.input[0].previous_output.txid = Txid::from_byte_array([42; 32]);
                psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = script;
                psbt.update_input_with_descriptor(0, &descriptor).unwrap();
                let unknown = b64(&psbt.serialize());
                let options = Some(SignOptions {
                    sign_inputs: selected,
                    sighash: None,
                    finalize: false,
                });
                let native = wallet.sign_psbt(&unknown, options.clone()).unwrap_err();
                let external = wallet
                    .prepare_external_sign_psbt(&unknown, options)
                    .unwrap_err();
                assert!(native.contains("not classified"), "{native}");
                assert!(external.contains("not classified"), "{external}");
                // The same current snapshot still permits the classified input.
                assert!(wallet.sign_psbt(&encoded, None).is_ok());
            }
        }
    }

    #[test]
    fn rejects_unknown_owned_key_with_caller_supplied_taproot_tree() {
        use bdk_wallet::miniscript::psbt::PsbtExt;
        let (mut wallet, encoded) = setup();
        let mut psbt = decode(&encoded);
        let descriptor = wallet
            .vault_wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(100_000)
            .unwrap();
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = descriptor
            .derived_descriptor(wallet.vault_wallet.secp_ctx())
            .unwrap()
            .script_pubkey();
        psbt.update_input_with_descriptor(0, &descriptor).unwrap();
        let root = bitcoin::taproot::TapNodeHash::from_byte_array([1; 32]);
        psbt.inputs[0].tap_merkle_root = Some(root);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::new_p2tr(
            wallet.vault_wallet.secp_ctx(),
            psbt.inputs[0].tap_internal_key.unwrap(),
            Some(root),
        );
        psbt.unsigned_tx.input[0].previous_output.txid = Txid::from_byte_array([42; 32]);
        let unknown = b64(&psbt.serialize());
        assert!(wallet
            .sign_psbt(&unknown, None)
            .unwrap_err()
            .contains("not classified"));
        assert!(wallet
            .prepare_external_sign_psbt(&unknown, None)
            .unwrap_err()
            .contains("not classified"));
    }

    #[test]
    fn rejects_selected_unknown_owned_input_in_mixed_psbt_but_allows_known_only_selection() {
        let (mut wallet, encoded) = setup();
        let mut psbt = decode(&encoded);
        let mut unknown = psbt.unsigned_tx.input[0].clone();
        unknown.previous_output.txid = Txid::from_byte_array([42; 32]);
        psbt.unsigned_tx.input.push(unknown);
        psbt.inputs.push(psbt.inputs[0].clone());
        psbt.unsigned_tx.output[0].value = Amount::from_sat(99_000);
        let mixed = b64(&psbt.serialize());
        assert!(wallet
            .sign_psbt(&mixed, None)
            .unwrap_err()
            .contains("not classified"));
        assert!(wallet
            .prepare_external_sign_psbt(&mixed, None)
            .unwrap_err()
            .contains("not classified"));
        let options = Some(SignOptions {
            sign_inputs: Some(vec![0]),
            sighash: None,
            finalize: false,
        });
        let signed = decode(&wallet.sign_psbt(&mixed, options.clone()).unwrap());
        assert!(signed.inputs[0].tap_key_sig.is_some());
        assert!(signed.inputs[1].tap_key_sig.is_none());
        assert!(wallet.prepare_external_sign_psbt(&mixed, options).is_ok());
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
    fn verify_rejects_structurally_valid_but_cryptographically_invalid_signature() {
        let (mut w, unsigned) = setup();
        let signed = sign_all(&mut w, &unsigned);
        let mut forged = decode(&signed);
        let mut signature_bytes = forged.inputs[0]
            .tap_key_sig
            .expect("taproot signature")
            .to_vec();
        signature_bytes[0] ^= 1;
        forged.inputs[0].tap_key_sig = Some(
            bitcoin::taproot::Signature::from_slice(&signature_bytes)
                .expect("mutated bytes remain structurally valid"),
        );

        let err = w
            .verify_external_signed_psbt(&unsigned, &b64(&forged.serialize()), None, false)
            .expect_err("a signature from the wrong key/message must fail");
        assert!(err.contains("invalid Taproot signature"), "{err}");
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

    #[test]
    fn signing_and_external_preparation_require_current_asset_classification() {
        let (mut wallet, unsigned) = setup();
        wallet.mark_ordinals_unverified();

        let sign_error = wallet.sign_psbt(&unsigned, None).unwrap_err();
        assert!(sign_error.contains("missing or stale"), "{sign_error}");
        let prepare_error = wallet
            .prepare_external_sign_psbt(&unsigned, None)
            .unwrap_err();
        assert!(
            prepare_error.contains("missing or stale"),
            "{prepare_error}"
        );
    }

    #[test]
    fn signing_and_external_preparation_reject_unclassified_wallet_input() {
        let (mut wallet, unsigned) = setup();
        wallet.classified_outpoints.clear();

        let sign_error = wallet.sign_psbt(&unsigned, None).unwrap_err();
        assert!(sign_error.contains("was not classified"), "{sign_error}");
        let prepare_error = wallet
            .prepare_external_sign_psbt(&unsigned, None)
            .unwrap_err();
        assert!(
            prepare_error.contains("was not classified"),
            "{prepare_error}"
        );
    }

    #[test]
    fn signing_and_external_preparation_reject_known_inscription_burn() {
        use crate::ordinals::types::{Inscription, Satpoint};

        let (mut wallet, unsigned) = setup();
        let psbt = decode(&unsigned);
        let outpoint = psbt.unsigned_tx.input[0].previous_output;
        wallet
            .apply_verified_ordinals_update(
                vec![Inscription {
                    id: "burn-test-inscription".to_string(),
                    number: 1,
                    satpoint: Satpoint {
                        outpoint,
                        offset: 49_500,
                    },
                    content_type: None,
                    value: Some(50_000),
                    content_length: None,
                    timestamp: None,
                }],
                [outpoint].into_iter().collect(),
                Vec::new(),
                [outpoint].into_iter().collect(),
                wallet.chain_state_generation(),
            )
            .unwrap();

        let sign_error = wallet.sign_psbt(&unsigned, None).unwrap_err();
        assert!(
            sign_error.contains("would burn inscription"),
            "{sign_error}"
        );
        let prepare_error = wallet
            .prepare_external_sign_psbt(&unsigned, None)
            .unwrap_err();
        assert!(
            prepare_error.contains("would burn inscription"),
            "{prepare_error}"
        );
    }

    #[test]
    fn signing_and_external_preparation_reject_nonzero_op_return_inscription_burn() {
        use crate::ordinals::types::{Inscription, Satpoint};

        let (mut wallet, unsigned) = setup();
        let mut psbt = decode(&unsigned);
        psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_op_return([]);
        let outpoint = psbt.unsigned_tx.input[0].previous_output;
        let op_return_psbt = b64(&psbt.serialize());

        wallet
            .apply_verified_ordinals_update(
                vec![Inscription {
                    id: "op-return-burn-test-inscription".to_string(),
                    number: 1,
                    satpoint: Satpoint {
                        outpoint,
                        offset: 0,
                    },
                    content_type: None,
                    value: Some(50_000),
                    content_length: None,
                    timestamp: None,
                }],
                [outpoint].into_iter().collect(),
                Vec::new(),
                [outpoint].into_iter().collect(),
                wallet.chain_state_generation(),
            )
            .unwrap();

        let sign_error = wallet.sign_psbt(&op_return_psbt, None).unwrap_err();
        assert!(
            sign_error.contains("would burn inscription"),
            "{sign_error}"
        );
        let prepare_error = wallet
            .prepare_external_sign_psbt(&op_return_psbt, None)
            .unwrap_err();
        assert!(
            prepare_error.contains("would burn inscription"),
            "{prepare_error}"
        );
    }

    #[test]
    fn absurd_fee_ceiling_is_identical_for_software_and_external_signing() {
        use crate::builder::ABSURD_FEE_SATS;

        let (mut at_boundary_wallet, at_boundary) =
            setup_with_values(2_000_000, 2_000_000 - ABSURD_FEE_SATS);
        at_boundary_wallet
            .sign_psbt(&at_boundary, None)
            .expect("the exact absolute boundary remains signable");
        let (at_boundary_wallet, at_boundary) =
            setup_with_values(2_000_000, 2_000_000 - ABSURD_FEE_SATS);
        at_boundary_wallet
            .prepare_external_sign_psbt(&at_boundary, None)
            .expect("the exact external-signing boundary remains signable");

        let absurd_fee = ABSURD_FEE_SATS + 1;
        let (mut software_wallet, software_psbt) =
            setup_with_values(2_000_000, 2_000_000 - absurd_fee);
        let software_error = software_wallet.sign_psbt(&software_psbt, None).unwrap_err();
        assert!(
            software_error.contains("absurd mining fee"),
            "{software_error}"
        );

        let (external_wallet, external_psbt) = setup_with_values(2_000_000, 2_000_000 - absurd_fee);
        let external_error = external_wallet
            .prepare_external_sign_psbt(&external_psbt, None)
            .unwrap_err();
        assert!(
            external_error.contains("absurd mining fee"),
            "{external_error}"
        );
    }

    #[test]
    fn capability_enforced_preparation_returns_psbt_and_exact_requirements() {
        use crate::external_signing::{
            ExternalSignerCapabilitiesV2, ExternalSignerInputPolicyV2,
            ExternalSigningInputRequirementV2, ExternalSigningInputTypeV1,
            ExternalSigningOutputTypeV1,
        };

        let (wallet, unsigned) = setup();
        let mut capabilities = ExternalSignerCapabilitiesV2::deny_all("test:taproot-signer");
        capabilities.input_signing_policies = vec![ExternalSignerInputPolicyV2 {
            input_type: ExternalSigningInputTypeV1::P2trKeyPath,
            supported_sighash_types: [0].into_iter().collect(),
            default_sighash_type: 0,
        }];
        capabilities
            .supported_output_types
            .insert(ExternalSigningOutputTypeV1::P2tr);

        let request = wallet
            .prepare_external_signing_request(&unsigned, None, &capabilities)
            .expect("compatible signer");

        assert!(!request.prepared_psbt_base64.is_empty());
        assert_eq!(
            request.requirements.required_inputs,
            vec![ExternalSigningInputRequirementV2 {
                index: 0,
                input_type: ExternalSigningInputTypeV1::P2trKeyPath,
                sighash_type: 0,
            }]
        );
        assert_eq!(request.signing_plan.inputs.len(), 1);
        assert_eq!(request.signing_plan.outputs.len(), 1);
        assert_eq!(
            request.signing_plan.inputs[0].input_type,
            ExternalSigningInputTypeV1::P2trKeyPath
        );
        assert_eq!(request.signing_plan.inputs[0].sighash_type, 0);
        let input_origin = request.signing_plan.inputs[0]
            .derivation
            .as_ref()
            .expect("input plan must carry a derivation path");
        assert!(
            input_origin.path.starts_with("m/86'/1'/0'"),
            "input plan must carry the exact BIP86 leaf path; got {}",
            input_origin.path
        );
        assert!(
            request.signing_plan.outputs[0].derivation.is_some(),
            "wallet-owned output must be represented as path-based change"
        );
    }

    #[test]
    fn raw_signed_transaction_is_merged_only_when_unsigned_fields_match() {
        use bitcoin::consensus::encode::serialize_hex;

        let (mut wallet, unsigned) = setup();
        let partially_signed = sign_all(&mut wallet, &unsigned);
        let finalized = wallet
            .verify_external_signed_psbt(&unsigned, &partially_signed, None, true)
            .expect("finalize signed fixture");
        let signed_tx = decode(&finalized).extract_tx_unchecked_fee_rate();
        let merged = wallet
            .apply_external_signed_transaction(&unsigned, &serialize_hex(&signed_tx))
            .expect("merge raw signer result");
        wallet
            .verify_external_signed_psbt(&unsigned, &merged, None, true)
            .expect("merged raw transaction remains verifiable");

        let mut modified = signed_tx;
        modified.output[0].value = Amount::from_sat(1);
        let error = wallet
            .apply_external_signed_transaction(&unsigned, &serialize_hex(&modified))
            .unwrap_err();
        assert!(error.contains("modified transaction"), "{error}");
    }

    #[test]
    fn capability_enforced_preparation_returns_typed_rejection() {
        use crate::external_signing::{
            ExternalSignerCapabilitiesV2, PrepareExternalSigningErrorV2,
        };

        let (wallet, unsigned) = setup();
        let capabilities = ExternalSignerCapabilitiesV2::deny_all("test:deny-all");
        let error = wallet
            .prepare_external_signing_request(&unsigned, None, &capabilities)
            .unwrap_err();

        let PrepareExternalSigningErrorV2::CapabilityRejected {
            requirements,
            compatibility,
        } = error
        else {
            panic!("expected typed capability rejection");
        };
        assert_eq!(requirements.required_inputs[0].index, 0);
        assert_eq!(
            compatibility.rejections[0].capability,
            "input.p2tr_key_path"
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

        wallet
            .apply_verified_ordinals_update(
                Vec::new(),
                std::collections::HashSet::new(),
                Vec::new(),
                std::collections::HashSet::new(),
                wallet.chain_state_generation(),
            )
            .unwrap();
        assert!(wallet.ordinals_verified());
        let asset_generation = wallet.asset_data_generation();
        wallet.mark_ordinals_unverified();
        assert!(!wallet.ordinals_verified());
        assert_eq!(
            wallet.asset_data_generation(),
            asset_generation.wrapping_add(1)
        );
        wallet.mark_ordinals_unverified();
        assert_eq!(
            wallet.asset_data_generation(),
            asset_generation.wrapping_add(1),
            "repeating an already-unverified state must not churn publication"
        );
    }

    #[test]
    fn empty_chain_update_preserves_generation_and_verified_asset_state() {
        let (mut wallet, _) = setup();
        let generation = wallet.chain_state_generation();
        let wallet_data_generation = wallet.wallet_data_generation();
        let asset_data_generation = wallet.asset_data_generation();
        assert!(wallet.ordinals_verified());

        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: Default::default(),
                    chain: Default::default(),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();
        assert_eq!(wallet.chain_state_generation(), generation,);
        assert_eq!(wallet.wallet_data_generation(), wallet_data_generation);
        assert_eq!(wallet.asset_data_generation(), asset_data_generation);
        assert!(wallet.ordinals_verified());
    }

    #[test]
    fn irrelevant_tip_change_does_not_advance_public_wallet_data() {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0x77; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let chain_generation = wallet.chain_state_generation();
        let wallet_data_generation = wallet.wallet_data_generation();
        let current_tip = wallet.vault_wallet.latest_checkpoint();
        let next_height = current_tip.height().saturating_add(1);
        let next_tip = current_tip.insert(BlockId {
            height: next_height,
            hash: BlockHash::from_byte_array([0x77; 32]),
        });

        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: Default::default(),
                    chain: Some(next_tip),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();

        assert_eq!(
            wallet.chain_state_generation(),
            chain_generation.wrapping_add(1),
            "the security generation still tracks the best-chain change"
        );
        assert_eq!(
            wallet.wallet_data_generation(),
            wallet_data_generation,
            "an empty wallet has no public confirmation or owned-output change"
        );
    }

    #[test]
    fn chain_tip_change_advances_generation_and_invalidates_assets() {
        let (mut wallet, _) = setup();
        let generation = wallet.chain_state_generation();
        let wallet_data_generation = wallet.wallet_data_generation();
        let asset_data_generation = wallet.asset_data_generation();
        let current_tip = wallet.vault_wallet.latest_checkpoint();
        let next_height = current_tip.height().saturating_add(1);
        let next_tip = current_tip.insert(BlockId {
            height: next_height,
            hash: BlockHash::from_byte_array([3; 32]),
        });

        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: Default::default(),
                    chain: Some(next_tip),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();

        assert_eq!(wallet.chain_state_generation(), generation.wrapping_add(1));
        assert_eq!(
            wallet.wallet_data_generation(),
            wallet_data_generation.wrapping_add(1),
            "a funded UTXO's confirmation count changes at a new tip"
        );
        assert_eq!(
            wallet.asset_data_generation(),
            asset_data_generation.wrapping_add(1)
        );
        assert!(!wallet.ordinals_verified());
    }

    #[test]
    fn material_owned_output_change_advances_generation_and_invalidates_assets() {
        let (mut wallet, _) = setup();
        let stale_generation = wallet.chain_state_generation();
        let wallet_data_generation = wallet.wallet_data_generation();
        assert!(wallet.ordinals_verified());

        let existing = wallet
            .vault_wallet
            .list_unspent()
            .next()
            .expect("funded fixture");
        let mut next = dummy_tx(25_000, existing.txout.script_pubkey, 2);
        next.input[0].previous_output = existing.outpoint;
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let next_txid = next.compute_txid();
        let _ = graph.insert_tx(next);
        let _ = graph.insert_seen_at(next_txid, 2_000);

        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: graph.into(),
                    chain: Default::default(),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();

        assert_eq!(
            wallet.chain_state_generation(),
            stale_generation.wrapping_add(1)
        );
        assert_eq!(
            wallet.wallet_data_generation(),
            wallet_data_generation.wrapping_add(1)
        );
        assert!(!wallet.ordinals_verified());
        let error = wallet
            .apply_verified_ordinals_update(
                Vec::new(),
                std::collections::HashSet::new(),
                Vec::new(),
                std::collections::HashSet::new(),
                stale_generation,
            )
            .unwrap_err();
        assert!(error.contains("Stale ordinals update"), "{error}");
    }

    #[test]
    fn inscription_transfer_snapshot_reuses_verified_owned_output_facts() {
        use crate::ordinals::types::{Inscription, Satpoint};

        let (mut wallet, _) = setup();
        let selected = wallet
            .vault_wallet
            .list_unspent()
            .next()
            .expect("funded fixture");
        let inscription_id = format!("{}i0", selected.outpoint.txid);
        wallet.inscriptions.push(Inscription {
            id: inscription_id.clone(),
            number: 1,
            satpoint: Satpoint {
                outpoint: selected.outpoint,
                offset: 0,
            },
            content_type: Some("image/png".to_string()),
            value: Some(selected.txout.value.to_sat()),
            content_length: None,
            timestamp: None,
        });
        wallet.inscribed_utxos.insert(selected.outpoint);
        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: Default::default(),
                    chain: Default::default(),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();

        let snapshot = wallet
            .inscription_transfer_construction_snapshot(std::slice::from_ref(&inscription_id))
            .expect("current verified state should produce a snapshot");
        assert_eq!(snapshot.inscriptions().len(), 1);
        assert_eq!(snapshot.inscriptions()[0].inscription_id(), inscription_id);
        assert_eq!(snapshot.inscriptions()[0].txout(), &selected.txout);
        assert!(snapshot.fee_inputs().is_empty());
        assert!(wallet.inscription_transfer_snapshot_is_current(&snapshot));

        wallet
            .apply_sync(
                bdk_wallet::Update {
                    tx_update: Default::default(),
                    chain: Default::default(),
                    last_active_indices: Default::default(),
                },
                None::<bdk_wallet::Update>,
            )
            .unwrap();
        assert!(wallet.inscription_transfer_snapshot_is_current(&snapshot));
    }

    #[test]
    fn inscription_transfer_snapshot_rejects_stale_or_syncing_facts() {
        use crate::ordinals::types::{Inscription, Satpoint};

        let (mut wallet, _) = setup();
        let selected = wallet
            .vault_wallet
            .list_unspent()
            .next()
            .expect("funded fixture");
        let inscription_id = format!("{}i0", selected.outpoint.txid);
        wallet.inscriptions.push(Inscription {
            id: inscription_id.clone(),
            number: 1,
            satpoint: Satpoint {
                outpoint: selected.outpoint,
                offset: 0,
            },
            content_type: Some("image/png".to_string()),
            value: Some(selected.txout.value.to_sat()),
            content_length: None,
            timestamp: None,
        });
        wallet.inscribed_utxos.insert(selected.outpoint);

        wallet.chain_observed_at_unix = Some(0);
        let stale_error = wallet
            .inscription_transfer_construction_snapshot(std::slice::from_ref(&inscription_id))
            .err()
            .expect("stale construction facts must not be reused");
        assert!(stale_error.contains("stale"), "{stale_error}");

        wallet.chain_observed_at_unix = wallet.ordinals_observed_at_unix;
        wallet.is_syncing = true;
        let syncing_error = wallet
            .inscription_transfer_construction_snapshot(std::slice::from_ref(&inscription_id))
            .err()
            .expect("in-flight sync must block snapshot reuse");
        assert!(
            syncing_error.contains("sync is in progress"),
            "{syncing_error}"
        );
    }
}
