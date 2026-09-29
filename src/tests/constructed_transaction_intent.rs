#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{
        AddressScheme, CancelIntentRequest, CoinControlAction, CoinControlIntentRequest,
        ConstructedTransactionIntent, ConstructedTransactionIntentRequest, CpfpIntentRequest,
        InscriptionTransferIntentRequest, Seed64, SignOptions, SmartSendWithSalvageIntentRequest,
        WalletBuilder, ZincWallet,
    };
    use crate::external_signing::{
        ExternalSignerCapabilitiesV2, ExternalSignerInputPolicyV2, ExternalSigningInputTypeV1,
        ExternalSigningOutputTypeV1,
    };
    use crate::ordinals::types::{Inscription, Satpoint};
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;
    use bitcoin::psbt::Psbt;

    fn setup(inscribed: bool, external_recipient: bool) -> (ZincWallet, String, OutPoint, String) {
        setup_with_scheme(inscribed, external_recipient, AddressScheme::Unified)
    }

    fn setup_with_scheme(
        inscribed: bool,
        external_recipient: bool,
        scheme: AddressScheme,
    ) -> (ZincWallet, String, OutPoint, String) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([31; 64]))
            .with_scheme(scheme)
            .build()
            .unwrap();
        let own = wallet
            .payment_wallet
            .as_mut()
            .unwrap_or(&mut wallet.vault_wallet)
            .reveal_next_address(KeychainKind::External)
            .address;
        let recipient = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([32; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap()
            .peek_taproot_address(0);
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([33; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: own.script_pubkey(),
            }],
        };
        let funding_outpoint = OutPoint::new(funding.compute_txid(), 0);
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_tx(funding.clone());
        let _ = graph.insert_anchor(
            funding.compute_txid(),
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 100,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 1_000,
            },
        );
        wallet
            .payment_wallet
            .as_mut()
            .unwrap_or(&mut wallet.vault_wallet)
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: [(KeychainKind::External, 0)].into_iter().collect(),
            })
            .unwrap();
        wallet.mark_current_wallet_outpoints_classified_for_test();
        if inscribed {
            wallet.inscribed_utxos.insert(funding_outpoint);
            wallet.inscriptions.push(Inscription {
                id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai0"
                    .to_string(),
                number: 1,
                satpoint: Satpoint {
                    outpoint: funding_outpoint,
                    offset: 0,
                },
                content_type: Some("text/plain".to_string()),
                value: Some(100_000),
                content_length: Some(1),
                timestamp: Some(1),
            });
        }

        let primary_output = if external_recipient {
            TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: recipient.script_pubkey(),
            }
        } else {
            TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: own.script_pubkey(),
            }
        };
        let mut outputs = vec![primary_output];
        if external_recipient {
            outputs.push(TxOut {
                value: Amount::from_sat(74_000),
                script_pubkey: own.script_pubkey(),
            });
        }
        let unsigned = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
        let encoded = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
        (wallet, encoded, funding_outpoint, recipient.to_string())
    }

    fn decode(encoded: &str) -> Psbt {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        Psbt::deserialize(&bytes).unwrap()
    }

    fn encode(psbt: &Psbt) -> String {
        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
    }

    fn capabilities() -> ExternalSignerCapabilitiesV2 {
        let mut capabilities = ExternalSignerCapabilitiesV2::deny_all("test:constructed");
        capabilities.input_signing_policies = vec![ExternalSignerInputPolicyV2 {
            input_type: ExternalSigningInputTypeV1::P2trKeyPath,
            supported_sighash_types: [0].into_iter().collect(),
            default_sighash_type: 0,
        }];
        capabilities
            .supported_output_types
            .insert(ExternalSigningOutputTypeV1::P2tr);
        capabilities
    }

    #[test]
    fn operation_intents_cross_software_and_hardware_boundaries() {
        let (mut wallet, psbt_base64, outpoint, _) = setup(false, false);
        let requests = vec![
            ConstructedTransactionIntentRequest::Cpfp(CpfpIntentRequest {
                requested_txid: outpoint.txid.to_string(),
                parent_txid: outpoint.txid.to_string(),
                anchor_outpoint: outpoint.to_string(),
            }),
            ConstructedTransactionIntentRequest::CoinControl(CoinControlIntentRequest {
                action: CoinControlAction::Split,
                selected_outpoints: vec![outpoint.to_string()],
            }),
        ];
        for request in requests {
            let psbt = decode(&psbt_base64);
            let intent = wallet
                .create_constructed_transaction_intent(&psbt, request)
                .unwrap();
            wallet
                .prepare_external_constructed_transaction_signing_request(
                    &psbt_base64,
                    &intent,
                    None,
                    &capabilities(),
                )
                .unwrap();
            wallet
                .sign_constructed_transaction_psbt(
                    &psbt_base64,
                    &intent,
                    Some(SignOptions {
                        finalize: true,
                        ..Default::default()
                    }),
                )
                .unwrap();
            let companion_psbt = wallet
                .prepare_companion_constructed_transaction_psbt(&psbt_base64, &intent)
                .unwrap();
            wallet
                .sign_companion_constructed_transaction_psbt(
                    &companion_psbt,
                    &intent,
                    Some(SignOptions {
                        finalize: true,
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
    }

    #[test]
    fn inscription_and_smart_salvage_intents_bind_assets_and_recipient() {
        let (mut wallet, psbt_base64, outpoint, recipient) = setup(true, true);
        let inscription_id = wallet.inscriptions[0].id.clone();
        let inscription_intent = wallet
            .create_constructed_transaction_intent(
                &decode(&psbt_base64),
                ConstructedTransactionIntentRequest::InscriptionTransfer(
                    InscriptionTransferIntentRequest {
                        inscription_ids: vec![inscription_id],
                        recipient: recipient.clone(),
                    },
                ),
            )
            .unwrap();
        wallet
            .prepare_external_constructed_transaction_signing_request(
                &psbt_base64,
                &inscription_intent,
                None,
                &capabilities(),
            )
            .unwrap();
        wallet
            .sign_constructed_transaction_psbt(&psbt_base64, &inscription_intent, None)
            .unwrap();

        // A smart salvage keeps the inscription's first sat in wallet-owned
        // postage, then pays the external BTC recipient from later sats.
        let own_script = wallet.peek_taproot_address(0).script_pubkey();
        let recipient_script = recipient
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey();
        let mut smart_psbt = decode(&psbt_base64);
        smart_psbt.unsigned_tx.output = vec![
            TxOut {
                value: Amount::from_sat(546),
                script_pubkey: own_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: recipient_script,
            },
            TxOut {
                value: Amount::from_sat(73_454),
                script_pubkey: own_script,
            },
        ];
        smart_psbt.outputs = vec![Default::default(), Default::default(), Default::default()];
        let smart_base64 = encode(&smart_psbt);
        let smart_intent = wallet
            .create_constructed_transaction_intent(
                &smart_psbt,
                ConstructedTransactionIntentRequest::SmartSendWithSalvage(
                    SmartSendWithSalvageIntentRequest {
                        recipient,
                        amount_sats: 25_000,
                        selected_outpoints: vec![outpoint.to_string()],
                    },
                ),
            )
            .unwrap();
        wallet
            .prepare_external_constructed_transaction_signing_request(
                &smart_base64,
                &smart_intent,
                None,
                &capabilities(),
            )
            .unwrap();
        wallet
            .sign_constructed_transaction_psbt(&smart_base64, &smart_intent, None)
            .unwrap();
    }

    #[test]
    fn exact_template_mutations_fail_at_software_and_hardware_boundaries() {
        let (mut wallet, psbt_base64, outpoint, _) = setup(false, false);
        let intent = wallet
            .create_constructed_transaction_intent(
                &decode(&psbt_base64),
                ConstructedTransactionIntentRequest::Cpfp(CpfpIntentRequest {
                    requested_txid: outpoint.txid.to_string(),
                    parent_txid: outpoint.txid.to_string(),
                    anchor_outpoint: outpoint.to_string(),
                }),
            )
            .unwrap();
        let mut mutations = Vec::new();

        let mut amount = decode(&psbt_base64);
        amount.unsigned_tx.output[0].value = Amount::from_sat(98_999);
        mutations.push(amount);

        let mut input = decode(&psbt_base64);
        input.unsigned_tx.input[0].previous_output.vout = 1;
        mutations.push(input);

        let mut sequence = decode(&psbt_base64);
        sequence.unsigned_tx.input[0].sequence = bitcoin::Sequence::MAX;
        mutations.push(sequence);

        let mut output = decode(&psbt_base64);
        output.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        });
        output.outputs.push(Default::default());
        mutations.push(output);

        for mutation in mutations {
            let encoded = encode(&mutation);
            let software_error = wallet
                .sign_constructed_transaction_psbt(&encoded, &intent, None)
                .unwrap_err();
            assert!(
                software_error.contains("Security Violation"),
                "{software_error}"
            );
            let hardware_error = wallet
                .prepare_external_constructed_transaction_signing_request(
                    &encoded,
                    &intent,
                    None,
                    &capabilities(),
                )
                .unwrap_err();
            assert!(
                hardware_error.to_string().contains("Security Violation"),
                "{hardware_error}"
            );
        }
    }

    fn pending_cancellation(scheme: AddressScheme) -> (ZincWallet, Psbt, Txid, OutPoint) {
        let (mut wallet, encoded, funding_outpoint, _) = setup_with_scheme(false, true, scheme);
        let original = decode(&encoded);
        let original_txid = original.unsigned_tx.compute_txid();
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_tx(original.unsigned_tx.clone());
        let _ = graph.insert_seen_at(original_txid, 2_000);
        wallet
            .payment_wallet
            .as_mut()
            .unwrap_or(&mut wallet.vault_wallet)
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: Default::default(),
            })
            .unwrap();
        wallet.mark_current_wallet_outpoints_classified_for_test();
        assert!(!wallet
            .collect_utxo_outpoints()
            .iter()
            .any(|(outpoint, _)| *outpoint == funding_outpoint.to_string()));
        let mut cancellation = original.clone();
        cancellation.unsigned_tx.output = vec![TxOut {
            value: Amount::from_sat(98_000),
            script_pubkey: original.unsigned_tx.output[1].script_pubkey.clone(),
        }];
        cancellation.outputs = vec![Default::default()];
        (wallet, cancellation, original_txid, funding_outpoint)
    }

    fn cancel_intent(
        wallet: &ZincWallet,
        psbt: &Psbt,
        original: Txid,
        input: OutPoint,
    ) -> ConstructedTransactionIntent {
        wallet
            .create_constructed_transaction_intent(
                psbt,
                ConstructedTransactionIntentRequest::Cancel(CancelIntentRequest {
                    original_txid: original.to_string(),
                    conflict_outpoints: vec![input.to_string()],
                }),
            )
            .unwrap()
    }

    #[test]
    fn cancel_after_pending_parent_sync_keeps_original_inputs_signable() {
        for scheme in [AddressScheme::Unified, AddressScheme::Dual] {
            let (mut wallet, cancellation, original, input) = pending_cancellation(scheme);
            let intent = cancel_intent(&wallet, &cancellation, original, input);
            assert!(wallet
                .sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None)
                .is_err());
            let before = wallet.get_balance().total;
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            assert_eq!(snapshot.ord_queries(), vec![(input.to_string(), 100_000)]);
            wallet
                .apply_verified_cancellation_inputs(snapshot.test_with_assets(Default::default()))
                .unwrap();
            let signed = wallet
                .sign_constructed_transaction_psbt(
                    &encode(&cancellation),
                    &intent,
                    Some(SignOptions {
                        finalize: true,
                        ..Default::default()
                    }),
                )
                .unwrap();
            assert!(decode(&signed).inputs[0].final_script_witness.is_some());
            assert_eq!(wallet.get_balance().total, before);
            if scheme == AddressScheme::Unified {
                wallet
                    .prepare_external_constructed_transaction_signing_request(
                        &encode(&cancellation),
                        &intent,
                        None,
                        &capabilities(),
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn cancellation_evidence_is_retired_by_every_wallet_generation() {
        for generation in 0..3 {
            let (mut wallet, cancellation, original, input) =
                pending_cancellation(AddressScheme::Unified);
            let intent = cancel_intent(&wallet, &cancellation, original, input);
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            wallet
                .apply_verified_cancellation_inputs(
                    snapshot.clone().test_with_assets(Default::default()),
                )
                .unwrap();
            match generation {
                0 => wallet.chain_state_generation += 1,
                1 => wallet.account_generation += 1,
                _ => wallet.asset_data_generation += 1,
            }
            assert!(wallet
                .apply_verified_cancellation_inputs(snapshot.test_with_assets(Default::default()))
                .is_err());
            assert!(wallet
                .sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None)
                .is_err());
        }
    }

    #[test]
    fn pending_input_inscriptions_are_analyzed_but_never_added_to_wallet_holdings() {
        for offset in [0, 99_000] {
            let (mut wallet, cancellation, original, input) =
                pending_cancellation(AddressScheme::Unified);
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            let id = format!("{}i0", "ab".repeat(32));
            let mut assets = crate::ordinals::client::ResolvedAssets::default();
            assets.inscriptions.push(Inscription {
                id: id.clone(),
                number: 1,
                satpoint: Satpoint {
                    outpoint: input,
                    offset,
                },
                value: Some(100_000),
                content_type: Some("text/plain".into()),
                content_length: Some(1),
                timestamp: Some(1),
            });
            assets.protected_outpoints.insert(input);
            wallet
                .apply_verified_cancellation_inputs(snapshot.test_with_assets(assets))
                .unwrap();
            assert!(wallet.inscriptions.is_empty());
            let analysis: serde_json::Value =
                serde_json::from_str(&wallet.analyze_psbt(&encode(&cancellation)).unwrap())
                    .unwrap();
            assert!(analysis["inscription_destinations"].get(&id).is_some());
            let intent = cancel_intent(&wallet, &cancellation, original, input);
            let result =
                wallet.sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None);
            if offset == 0 {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().contains("burn inscription"));
            }
        }
    }

    #[test]
    fn pending_input_rare_sats_cannot_enter_the_fee_tail() {
        let (mut wallet, cancellation, original, input) =
            pending_cancellation(AddressScheme::Unified);
        let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
        let mut assets = crate::ordinals::client::ResolvedAssets::default();
        let summary = crate::ordinals::client::validate_sat_ranges(
            &input.to_string(),
            Some(&[(5_000_000_000 - 99_000, 5_000_000_000 + 1_000)]),
            Some(100_000),
            100_000,
        )
        .unwrap();
        assert!(summary.count > 0);
        assets.rare_sat_outpoints.insert(input, summary);
        assets.protected_outpoints.insert(input);
        wallet
            .apply_verified_cancellation_inputs(snapshot.test_with_assets(assets))
            .unwrap();
        assert!(wallet.rare_sat_outpoints.is_empty());
        let intent = cancel_intent(&wallet, &cancellation, original, input);
        let error = wallet
            .sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None)
            .unwrap_err();
        assert!(error.contains("protected rare sat"), "{error}");
    }

    #[test]
    fn cancellation_publication_rejects_unrelated_asset_evidence() {
        let (mut wallet, _, original, _) = pending_cancellation(AddressScheme::Unified);
        let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
        let mut assets = crate::ordinals::client::ResolvedAssets::default();
        assets.protected_outpoints.insert(OutPoint::null());
        assert!(wallet
            .apply_verified_cancellation_inputs(snapshot.test_with_assets(assets))
            .is_err());
        assert!(wallet
            .cancellation_input_snapshot(Txid::all_zeros())
            .is_err());
    }

    #[tokio::test]
    async fn cancellation_proof_requires_complete_validated_ord_responses() {
        for fault in 0..9 {
            let (mut wallet, cancellation, original, input) =
                pending_cancellation(AddressScheme::Dual);
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            let mut output = serde_json::json!({ "outpoint": input.to_string(), "transaction": input.txid.to_string(),
                "indexed": true, "value": 100_000, "inscriptions": [], "runes": {},
                "sat_ranges": [[5_000_010_000_u64, 5_000_110_000_u64]] });
            match fault {
                1 => output["indexed"] = false.into(),
                2 => output["value"] = 99_999.into(),
                3 => output["transaction"] = Txid::all_zeros().to_string().into(),
                4 => output["sat_ranges"] = serde_json::Value::Null,
                5 => {
                    output.as_object_mut().unwrap().remove("inscriptions");
                }
                6 => output["runes"] = serde_json::Value::Null,
                7 => output["runes"] = serde_json::json!({"RUNE": {"amount":"not-an-amount"}}),
                _ => {}
            }
            let response = if fault == 8 {
                serde_json::json!([])
            } else {
                serde_json::json!([output])
            };
            let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
            let request = server
                .mock("POST", "/outputs")
                .match_body(mockito::Matcher::Json(serde_json::json!([
                    input.to_string()
                ])))
                .with_status(200)
                .with_body(response.to_string())
                .expect(1)
                .create_async()
                .await;
            let proof = snapshot.verify(&server.url()).await;
            if fault == 0 {
                wallet
                    .apply_verified_cancellation_inputs(proof.unwrap())
                    .unwrap();
                let intent = cancel_intent(&wallet, &cancellation, original, input);
                wallet
                    .sign_constructed_transaction_psbt(
                        &encode(&cancellation),
                        &intent,
                        Some(SignOptions {
                            finalize: true,
                            ..Default::default()
                        }),
                    )
                    .unwrap();
            } else {
                assert!(
                    proof.is_err(),
                    "malformed evidence case {fault} was accepted"
                );
                assert!(wallet.cancellation_assets().is_none());
            }
            request.assert_async().await;
        }
    }

    #[test]
    fn pending_input_runes_are_protected_without_inflating_holdings() {
        let (mut wallet, mut cancellation, original, input) =
            pending_cancellation(AddressScheme::Unified);
        // The whole Rune input must be returned. A distinct classified cardinal
        // input comes last and pays the fee without touching that input's sats.
        let cardinal = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([78; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: cancellation.unsigned_tx.output[0].script_pubkey.clone(),
            }],
        };
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_tx(cardinal.clone());
        let _ = graph.insert_seen_at(cardinal.compute_txid(), 3_000);
        wallet
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: Default::default(),
            })
            .unwrap();
        wallet.mark_current_wallet_outpoints_classified_for_test();
        let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
        let mut assets = crate::ordinals::client::ResolvedAssets::default();
        assets
            .outpoint_runes
            .insert(input, vec![("100:1".into(), 25)]);
        assets.protected_outpoints.insert(input);
        wallet
            .apply_verified_cancellation_inputs(snapshot.test_with_assets(assets))
            .unwrap();
        assert!(wallet.rune_balances.is_empty());
        assert!(wallet.outpoint_runes.is_empty());
        // The original one-input cancellation would consume Rune postage.
        let unsafe_intent = cancel_intent(&wallet, &cancellation, original, input);
        assert!(wallet
            .sign_constructed_transaction_psbt(&encode(&cancellation), &unsafe_intent, None)
            .unwrap_err()
            .contains("Rune postage"));
        assert!(wallet
            .prepare_external_constructed_transaction_signing_request(
                &encode(&cancellation),
                &unsafe_intent,
                None,
                &capabilities()
            )
            .unwrap_err()
            .to_string()
            .contains("Rune postage"));
        cancellation.unsigned_tx.input.push(TxIn {
            previous_output: OutPoint::new(cardinal.compute_txid(), 0),
            ..cancellation.unsigned_tx.input[0].clone()
        });
        cancellation.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(cardinal.output[0].clone()),
            ..Default::default()
        });
        cancellation.unsigned_tx.output[0].value = Amount::from_sat(108_000);
        let analysis: serde_json::Value =
            serde_json::from_str(&wallet.analyze_psbt(&encode(&cancellation)).unwrap()).unwrap();
        assert!(
            analysis["rune_actions"]["default_transfer_without_runestone"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            analysis["outputs"][0]["is_change"], false,
            "Receive ownership must not depend on change labeling"
        );
        let intent = cancel_intent(&wallet, &cancellation, original, input);
        wallet
            .sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None)
            .unwrap();
        wallet
            .prepare_external_constructed_transaction_signing_request(
                &encode(&cancellation),
                &intent,
                None,
                &capabilities(),
            )
            .unwrap();
        let mut reordered = cancellation.clone();
        reordered.unsigned_tx.input.swap(0, 1);
        reordered.inputs.swap(0, 1);
        let reordered_intent = cancel_intent(&wallet, &reordered, original, input);
        assert!(wallet
            .sign_constructed_transaction_psbt(&encode(&reordered), &reordered_intent, None)
            .unwrap_err()
            .contains("Rune postage"));
        let mut foreign = cancellation;
        foreign.unsigned_tx.output[0].script_pubkey =
            WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([77; 64]))
                .build()
                .unwrap()
                .peek_taproot_address(0)
                .script_pubkey();
        assert!(wallet
            .sign_psbt(&encode(&foreign), None)
            .unwrap_err()
            .contains("Runes would default-transfer"));
    }

    #[test]
    fn pending_asset_evidence_cannot_be_disguised_as_cardinal_coin_control() {
        for kind in ["inscription", "rune", "rare-sat"] {
            let (mut wallet, cancellation, original, input) =
                pending_cancellation(AddressScheme::Unified);
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            let mut assets = crate::ordinals::client::ResolvedAssets::default();
            assets.protected_outpoints.insert(input);
            if kind == "inscription" {
                assets.inscriptions.push(Inscription {
                    id: format!("{}i0", "ab".repeat(32)),
                    number: 1,
                    satpoint: Satpoint {
                        outpoint: input,
                        offset: 0,
                    },
                    value: Some(100_000),
                    content_type: None,
                    content_length: None,
                    timestamp: None,
                });
            } else if kind == "rune" {
                assets
                    .outpoint_runes
                    .insert(input, vec![("100:1".into(), 25)]);
            } else {
                assets.rare_sat_outpoints.insert(
                    input,
                    crate::ordinals::client::validate_sat_ranges(
                        &input.to_string(),
                        Some(&[(5_000_000_000, 5_000_100_000)]),
                        Some(100_000),
                        100_000,
                    )
                    .unwrap(),
                );
            }
            wallet
                .apply_verified_cancellation_inputs(snapshot.test_with_assets(assets))
                .unwrap();
            for action in [CoinControlAction::Split, CoinControlAction::Consolidate] {
                let intent = wallet.create_constructed_transaction_intent(
                    &cancellation,
                    ConstructedTransactionIntentRequest::CoinControl(CoinControlIntentRequest {
                        action,
                        selected_outpoints: vec![input.to_string()],
                    }),
                );
                assert!(
                    intent.is_err(),
                    "{kind} was accepted as a cardinal coin-control input"
                );
            }
            assert!(wallet.inscriptions.is_empty());
            assert!(wallet.outpoint_runes.is_empty());
            assert!(wallet.rare_sat_outpoints.is_empty());
        }
    }

    #[test]
    fn cancellation_target_confirmation_retires_verification_and_intent() {
        let (mut wallet, cancellation, original, input) =
            pending_cancellation(AddressScheme::Unified);
        let intent = cancel_intent(&wallet, &cancellation, original, input);
        let proof = wallet
            .cancellation_input_snapshot(original)
            .unwrap()
            .test_with_assets(Default::default());
        let block = BlockId {
            height: 101,
            hash: BlockHash::from_byte_array([93; 32]),
        };
        let checkpoint = wallet.vault_wallet.local_chain().tip().insert(block);
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_anchor(
            original,
            ConfirmationBlockTime {
                block_id: block,
                confirmation_time: 4_000,
            },
        );
        wallet
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Some(checkpoint),
                last_active_indices: Default::default(),
            })
            .unwrap();
        // Even if a host forgets to advance its generation, the canonical
        // transaction position invalidates evidence captured before confirmation.
        assert!(wallet
            .cancellation_input_snapshot(original)
            .unwrap_err()
            .contains("already confirmed"));
        assert!(wallet.apply_verified_cancellation_inputs(proof).is_err());
        assert!(wallet
            .sign_constructed_transaction_psbt(&encode(&cancellation), &intent, None)
            .is_err());
        assert!(wallet
            .prepare_external_constructed_transaction_signing_request(
                &encode(&cancellation),
                &intent,
                None,
                &capabilities()
            )
            .is_err());
    }

    #[test]
    fn cancellation_intent_rejects_a_substituted_target() {
        let (wallet, cancellation, original, input) = pending_cancellation(AddressScheme::Unified);
        let ConstructedTransactionIntent::Cancel(mut details) =
            cancel_intent(&wallet, &cancellation, original, input)
        else {
            unreachable!()
        };
        details.original_txid = input.txid.to_string();
        assert!(wallet
            .validate_constructed_transaction_psbt(
                &cancellation,
                &ConstructedTransactionIntent::Cancel(details)
            )
            .is_err());
    }

    #[test]
    fn verified_pending_inputs_never_trust_psbt_value_or_script_claims() {
        for scheme in [AddressScheme::Unified, AddressScheme::Dual] {
            let (mut wallet, cancellation, original, input) = pending_cancellation(scheme);
            let snapshot = wallet.cancellation_input_snapshot(original).unwrap();
            wallet
                .apply_verified_cancellation_inputs(snapshot.test_with_assets(Default::default()))
                .unwrap();
            let intent = cancel_intent(&wallet, &cancellation, original, input);
            for change_script in [false, true] {
                let mut mutation = cancellation.clone();
                let prevout = mutation.inputs[0].witness_utxo.as_mut().unwrap();
                if change_script {
                    prevout.script_pubkey = ScriptBuf::new();
                } else {
                    prevout.value = Amount::from_sat(100_001);
                }
                assert!(wallet
                    .sign_psbt(&encode(&mutation), None)
                    .unwrap_err()
                    .contains("different value or script"));
                assert!(wallet
                    .sign_constructed_transaction_psbt(&encode(&mutation), &intent, None)
                    .is_err());
                assert!(wallet
                    .prepare_external_constructed_transaction_signing_request(
                        &encode(&mutation),
                        &intent,
                        None,
                        &capabilities()
                    )
                    .is_err());
            }
        }
    }

    #[test]
    fn operation_specific_fields_cannot_be_substituted() {
        let (wallet, psbt_base64, outpoint, _) = setup(false, false);
        let psbt = decode(&psbt_base64);
        let cpfp = wallet
            .create_constructed_transaction_intent(
                &psbt,
                ConstructedTransactionIntentRequest::Cpfp(CpfpIntentRequest {
                    requested_txid: outpoint.txid.to_string(),
                    parent_txid: outpoint.txid.to_string(),
                    anchor_outpoint: outpoint.to_string(),
                }),
            )
            .unwrap();
        let ConstructedTransactionIntent::Cpfp(mut details) = cpfp else {
            unreachable!();
        };
        let mut wrong_parent = details.clone();
        wrong_parent.parent_txid = Txid::from_byte_array([46; 32]).to_string();
        assert!(wallet
            .validate_constructed_transaction_psbt(
                &psbt,
                &ConstructedTransactionIntent::Cpfp(wrong_parent)
            )
            .unwrap_err()
            .contains("approved parent"));

        details.anchor_outpoint = OutPoint::new(outpoint.txid, 9).to_string();
        assert!(wallet
            .validate_constructed_transaction_psbt(
                &psbt,
                &ConstructedTransactionIntent::Cpfp(details)
            )
            .unwrap_err()
            .contains("approved anchor"));

        let (wallet, psbt, original, outpoint) = pending_cancellation(AddressScheme::Unified);
        let cancel = cancel_intent(&wallet, &psbt, original, outpoint);
        let ConstructedTransactionIntent::Cancel(mut details) = cancel else {
            unreachable!();
        };
        details.conflict_outpoints = vec![OutPoint::new(outpoint.txid, 7).to_string()];
        assert!(wallet
            .validate_constructed_transaction_psbt(
                &psbt,
                &ConstructedTransactionIntent::Cancel(details)
            )
            .unwrap_err()
            .contains("no longer conflicts"));
    }
}
