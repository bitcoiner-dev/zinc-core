#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{
        AddressScheme, CreateRuneTransferRequest, Seed64, SignOptions, WalletBuilder, ZincWallet,
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
        wallet.ordinals_verified = true;
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
    }

    #[test]
    fn partial_send_uses_ord_runestone_change_recipient_order() {
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000]);
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
        let (mut wallet, _, outpoints) = funded_wallet(&[12_000]);
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
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000]);
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
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000]);
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
        let (mut wallet, _, outpoints) = funded_wallet(&[10_000]);
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
