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
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([31; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let own = wallet
            .vault_wallet
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
            .vault_wallet
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
            ConstructedTransactionIntentRequest::Cancel(CancelIntentRequest {
                original_txid: Txid::from_byte_array([44; 32]).to_string(),
                conflict_outpoints: vec![outpoint.to_string()],
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

        let cancel = wallet
            .create_constructed_transaction_intent(
                &psbt,
                ConstructedTransactionIntentRequest::Cancel(CancelIntentRequest {
                    original_txid: Txid::from_byte_array([55; 32]).to_string(),
                    conflict_outpoints: vec![outpoint.to_string()],
                }),
            )
            .unwrap();
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
