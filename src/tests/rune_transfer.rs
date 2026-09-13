#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{
        AddressScheme, CreateRuneTransferRequest, Seed64, SignOptions, WalletBuilder, WalletKind,
        ZincWallet,
    };
    use crate::error::ZincError;
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;
    use ordinals::{Artifact, Edict, RuneId, Runestone};

    const DOG: &str = "840000:3";
    const CAT: &str = "840001:1";

    fn dummy_tx(value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0_u8; 32];
        hash_bytes[31] = uid;
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(hash_bytes), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn funded_wallet(values: &[u64]) -> (ZincWallet, Address, Vec<OutPoint>) {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0_u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let address = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let mut outpoints = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let tx = dummy_tx(
                *value,
                address.script_pubkey(),
                u8::try_from(index + 1).unwrap(),
            );
            let txid = tx.compute_txid();
            let _ = graph.insert_tx(tx);
            let _ = graph.insert_anchor(
                txid,
                ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 100 + u32::try_from(index).unwrap(),
                        hash: BlockHash::all_zeros(),
                    },
                    confirmation_time: 1_000 + u64::try_from(index).unwrap(),
                },
            );
            outpoints.push(OutPoint::new(txid, 0));
        }
        let mut last_active = std::collections::BTreeMap::new();
        last_active.insert(KeychainKind::External, 0);
        wallet
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Default::default(),
                last_active_indices: last_active,
            })
            .unwrap();
        wallet.mark_current_wallet_outpoints_classified_for_test();
        (wallet, address, outpoints)
    }

    fn foreign_address() -> Address {
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([1_u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap()
            .peek_taproot_address(0)
    }

    fn request(amount: &str, recipient: &Address) -> CreateRuneTransferRequest {
        CreateRuneTransferRequest {
            rune_id: DOG.to_string(),
            amount: amount.to_string(),
            recipient: recipient.to_string(),
            fee_rate_sat_vb: 1.0,
            postage_sats: Some(546),
        }
    }

    fn decode_psbt(encoded: &str) -> bitcoin::Psbt {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        bitcoin::Psbt::deserialize(&bytes).unwrap()
    }

    #[test]
    fn postage_without_sufficient_cardinal_fees_is_refused() {
        for amount in ["60", "100"] {
            for values in [&[10_000][..], &[10_000, 100][..]] {
                let (mut wallet, _, outpoints) = funded_wallet(values);
                wallet
                    .outpoint_runes
                    .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
                wallet.inscribed_utxos.insert(outpoints[0]);
                let result = wallet.create_rune_transfer(&request(amount, &foreign_address()));
                assert!(
                    matches!(result, Err(ZincError::WalletError(message))
                    if message.contains("cardinal BTC")),
                    "Rune postage must not make up a fee shortfall"
                );
            }
        }
    }

    #[test]
    fn postage_is_preserved_before_the_fee_boundary_for_full_and_partial_sends() {
        for amount in ["60", "100"] {
            let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
            wallet
                .outpoint_runes
                .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
            wallet.inscribed_utxos.insert(outpoints[0]);
            let result = wallet
                .create_rune_transfer(&request(amount, &foreign_address()))
                .unwrap();
            let psbt = decode_psbt(&result.psbt);
            assert!(psbt.unsigned_tx.input.iter().any(|input| input.previous_output == outpoints[1]),
                "A classified cardinal input funds fees even when the Rune input has excess postage");
            let output_sats: u64 = psbt
                .unsigned_tx
                .output
                .iter()
                .map(|output| output.value.to_sat())
                .sum();
            let mut end = 0;
            for (input, prevout) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs) {
                end += prevout.witness_utxo.as_ref().unwrap().value.to_sat();
                if input.previous_output == outpoints[0] {
                    assert!(
                        end <= output_sats,
                        "Every sat from the Rune input reaches an output before fees"
                    );
                }
            }
            wallet
                .validate_rune_transfer_psbt(&psbt, &result.intent)
                .unwrap();
        }
    }

    #[test]
    fn postage_fee_and_input_order_tampering_are_refused_at_signing() {
        for amount in ["60", "100"] {
            let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
            wallet
                .outpoint_runes
                .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
            wallet.inscribed_utxos.insert(outpoints[0]);
            // Force a cardinal input even in the old constructor so this
            // regression reaches the independent signing validator before
            // the construction policy is fixed.
            let mut transfer = request(amount, &foreign_address());
            transfer.postage_sats = Some(10_000);
            let result = wallet.create_rune_transfer(&transfer).unwrap();
            let original = decode_psbt(&result.psbt);
            assert_eq!(original.unsigned_tx.input.len(), 2);
            let mut fee_theft = original.clone();
            for output in &mut fee_theft.unsigned_tx.output {
                if !output.script_pubkey.is_op_return() {
                    output.value = Amount::from_sat(546);
                }
            }
            let mut reordered = original;
            reordered.unsigned_tx.input.swap(0, 1);
            reordered.inputs.swap(0, 1);
            for altered in [fee_theft, reordered] {
                let error = wallet
                    .validate_rune_transfer_psbt(&altered, &result.intent)
                    .unwrap_err();
                assert!(error.contains("postage"), "{error}");
                let encoded = base64::engine::general_purpose::STANDARD.encode(altered.serialize());
                assert!(wallet
                    .sign_rune_transfer_psbt(&encoded, &result.intent, None)
                    .unwrap_err()
                    .contains("postage"));
                assert!(wallet
                    .prepare_companion_rune_transfer_psbt(&encoded, &result.intent)
                    .unwrap_err()
                    .to_string()
                    .contains("postage"));
            }
        }
    }

    #[test]
    fn exact_single_rune_send_uses_ord_default_transfer_shape() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);

        let recipient = foreign_address();
        let result = wallet
            .create_rune_transfer(&request("100", &recipient))
            .unwrap();
        let psbt = decode_psbt(&result.psbt);

        assert_eq!(result.intent.recipient_vout, 0);
        assert_eq!(result.rune_change_vout, None);
        assert_eq!(result.rune_input_outpoints, vec![outpoints[0].to_string()]);
        assert_eq!(
            psbt.unsigned_tx.output[0].script_pubkey,
            recipient.script_pubkey()
        );
        assert!(Runestone::decipher(&psbt.unsigned_tx).is_none());
        wallet
            .validate_rune_transfer_psbt(&psbt, &result.intent)
            .unwrap();
        assert_eq!(
            result.analysis.warning_level,
            crate::ordinals::shield::WarningLevel::Safe
        );
        wallet
            .sign_rune_transfer_psbt(
                &result.psbt,
                &result.intent,
                Some(SignOptions {
                    finalize: true,
                    ..Default::default()
                }),
            )
            .unwrap();
        let companion_psbt = wallet
            .prepare_companion_rune_transfer_psbt(&result.psbt, &result.intent)
            .unwrap();
        wallet
            .sign_companion_rune_transfer_psbt(
                &companion_psbt,
                &result.intent,
                Some(SignOptions {
                    finalize: true,
                    ..Default::default()
                }),
            )
            .unwrap();
    }

    #[test]
    fn companion_watch_wallet_can_construct_but_not_sign_a_rune_transfer() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);
        wallet.kind = WalletKind::Hardware {
            fingerprint: [0; 4],
            taproot_external: "test-companion-descriptor".to_string(),
            payment_external: None,
        };

        let request = request("100", &foreign_address());
        assert!(matches!(
            wallet.create_rune_transfer(&request),
            Err(ZincError::CapabilityMissing)
        ));

        let result = wallet.create_companion_rune_transfer(&request).unwrap();
        let signing_error = wallet
            .sign_rune_transfer_psbt(&result.psbt, &result.intent, None)
            .unwrap_err();
        assert_eq!(signing_error, ZincError::CapabilityMissing.to_string());
    }

    #[test]
    fn partial_send_uses_ord_runestone_change_recipient_order() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);

        let recipient = foreign_address();
        let result = wallet
            .create_rune_transfer(&request("60", &recipient))
            .unwrap();
        let psbt = decode_psbt(&result.psbt);

        assert_eq!(result.intent.recipient_vout, 2);
        assert_eq!(result.rune_change_vout, Some(1));
        assert!(psbt.unsigned_tx.output[0].script_pubkey.is_op_return());
        assert!(wallet
            .vault_wallet
            .is_mine(psbt.unsigned_tx.output[1].script_pubkey.clone()));
        assert_eq!(
            psbt.unsigned_tx.output[2].script_pubkey,
            recipient.script_pubkey()
        );
        assert!(matches!(
            Runestone::decipher(&psbt.unsigned_tx),
            Some(Artifact::Runestone(_))
        ));

        let analysis: crate::ordinals::shield::AnalysisResult =
            serde_json::from_str(&wallet.analyze_psbt(&result.psbt).unwrap()).unwrap();
        assert_eq!(analysis.outputs[1].runes[0].amount, "40");
        assert_eq!(analysis.outputs[2].runes[0].amount, "60");
    }

    #[test]
    fn co_located_non_target_rune_returns_to_owned_change() {
        let (mut wallet, _, outpoints) = funded_wallet(&[12_000, 20_000]);
        wallet.outpoint_runes.insert(
            outpoints[0],
            vec![(DOG.to_string(), 100), (CAT.to_string(), 7)],
        );
        wallet.inscribed_utxos.insert(outpoints[0]);

        let result = wallet
            .create_rune_transfer(&request("100", &foreign_address()))
            .unwrap();
        let analysis: crate::ordinals::shield::AnalysisResult =
            serde_json::from_str(&wallet.analyze_psbt(&result.psbt).unwrap()).unwrap();

        assert_eq!(analysis.outputs[1].runes[0].rune_id, CAT);
        assert_eq!(analysis.outputs[1].runes[0].amount, "7");
        assert_eq!(analysis.outputs[2].runes[0].rune_id, DOG);
    }

    #[test]
    fn insufficient_or_inscribed_rune_inputs_are_refused() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 50)]);
        wallet.inscribed_utxos.insert(outpoints[0]);

        let error = wallet
            .create_rune_transfer(&request("60", &foreign_address()))
            .unwrap_err();
        assert!(
            matches!(error, ZincError::WalletError(message) if message.contains("Insufficient Rune balance"))
        );

        wallet
            .inscriptions
            .push(crate::ordinals::types::Inscription {
                id: "co-locatedi0".to_string(),
                number: 0,
                satpoint: crate::ordinals::types::Satpoint {
                    outpoint: outpoints[0],
                    offset: 0,
                },
                content_type: None,
                value: Some(10_000),
                content_length: None,
                timestamp: None,
            });
        let error = wallet
            .create_rune_transfer(&request("50", &foreign_address()))
            .unwrap_err();
        assert!(
            matches!(error, ZincError::WalletError(message) if message.contains("Insufficient Rune balance"))
        );
    }

    #[test]
    fn signing_validation_rejects_recipient_mutation() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);
        let result = wallet
            .create_rune_transfer(&request("40", &foreign_address()))
            .unwrap();
        let mut psbt = decode_psbt(&result.psbt);
        psbt.unsigned_tx.output[2].script_pubkey = wallet.peek_taproot_address(0).script_pubkey();

        let error = wallet
            .validate_rune_transfer_psbt(&psbt, &result.intent)
            .unwrap_err();
        assert!(error.contains("approved address"));
    }

    #[test]
    fn insufficient_cardinal_postage_and_wrong_network_are_refused() {
        let (mut wallet, _, outpoints) = funded_wallet(&[600]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);

        let error = wallet
            .create_rune_transfer(&request("50", &foreign_address()))
            .unwrap_err();
        assert!(
            matches!(error, ZincError::WalletError(message) if message.contains("cardinal BTC"))
        );

        let mainnet_recipient =
            WalletBuilder::from_seed(Network::Bitcoin, Seed64::from_array([2_u8; 64]))
                .with_scheme(AddressScheme::Unified)
                .build()
                .unwrap()
                .peek_taproot_address(0);
        let error = wallet
            .create_rune_transfer(&request("50", &mainnet_recipient))
            .unwrap_err();
        assert!(
            matches!(error, ZincError::ConfigError(message) if message.contains("network mismatch"))
        );
    }

    #[test]
    fn signing_validation_rejects_wrong_allocation_and_missing_owned_change() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);
        let result = wallet
            .create_rune_transfer(&request("40", &foreign_address()))
            .unwrap();

        let mut wrong_amount = decode_psbt(&result.psbt);
        wrong_amount.unsigned_tx.output[0].script_pubkey = Runestone {
            edicts: vec![Edict {
                id: DOG.parse::<RuneId>().unwrap(),
                amount: 39,
                output: 2,
            }],
            ..Runestone::default()
        }
        .encipher();
        let error = wallet
            .validate_rune_transfer_psbt(&wrong_amount, &result.intent)
            .unwrap_err();
        assert!(error.contains("amount mismatch"));

        let mut stolen_change = decode_psbt(&result.psbt);
        stolen_change.unsigned_tx.output[1].script_pubkey = foreign_address().script_pubkey();
        let error = wallet
            .validate_rune_transfer_psbt(&stolen_change, &result.intent)
            .unwrap_err();
        assert!(error.contains("not owned"));
    }

    #[test]
    fn signing_validation_rejects_cenotaph() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000, 20_000]);
        wallet
            .outpoint_runes
            .insert(outpoints[0], vec![(DOG.to_string(), 100)]);
        wallet.inscribed_utxos.insert(outpoints[0]);
        let result = wallet
            .create_rune_transfer(&request("40", &foreign_address()))
            .unwrap();
        let mut psbt = decode_psbt(&result.psbt);
        psbt.unsigned_tx.output[0].script_pubkey = Runestone {
            edicts: vec![Edict {
                id: DOG.parse::<RuneId>().unwrap(),
                amount: 40,
                output: 99,
            }],
            ..Runestone::default()
        }
        .encipher();
        assert!(matches!(
            Runestone::decipher(&psbt.unsigned_tx),
            Some(Artifact::Cenotaph(_))
        ));

        let error = wallet
            .validate_rune_transfer_psbt(&psbt, &result.intent)
            .unwrap_err();
        assert!(error.contains("cenotaph"));
    }
}
