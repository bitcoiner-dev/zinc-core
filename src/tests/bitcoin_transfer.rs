#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{
        AddressScheme, CreatePsbtRequest, Seed64, SignOptions, WalletBuilder, ZincWallet,
    };
    use crate::external_signing::{
        ExternalSignerCapabilitiesV2, ExternalSignerInputPolicyV2, ExternalSigningInputTypeV1,
        ExternalSigningOutputTypeV1,
    };
    use base64::Engine;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;

    fn funded_wallet() -> ZincWallet {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let address = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let funding = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let txid = funding.compute_txid();
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let _ = graph.insert_tx(funding);
        let _ = graph.insert_anchor(
            txid,
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
        wallet
    }

    fn foreign_address() -> bdk_wallet::bitcoin::Address {
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap()
            .peek_taproot_address(0)
    }

    fn decode(encoded: &str) -> bitcoin::Psbt {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        bitcoin::Psbt::deserialize(&bytes).unwrap()
    }

    fn encode(psbt: &bitcoin::Psbt) -> String {
        base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
    }

    fn capabilities() -> ExternalSignerCapabilitiesV2 {
        let mut capabilities = ExternalSignerCapabilitiesV2::deny_all("test:taproot");
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
    fn engine_issued_intent_succeeds_for_software_and_hardware_boundaries() {
        let mut wallet = funded_wallet();
        let recipient = foreign_address();
        let request = CreatePsbtRequest::from_parts(&recipient.to_string(), 25_000, 2.0).unwrap();
        let result = wallet.create_bitcoin_transfer(&request).unwrap();
        let psbt = decode(&result.psbt);

        wallet
            .validate_bitcoin_transfer_psbt(&psbt, &result.intent)
            .unwrap();
        wallet
            .prepare_external_bitcoin_transfer_signing_request(
                &result.psbt,
                &result.intent,
                None,
                &capabilities(),
            )
            .unwrap();
        wallet
            .sign_bitcoin_transfer_psbt(
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
    fn recipient_amount_fee_and_input_mutations_are_rejected_at_both_boundaries() {
        let mut wallet = funded_wallet();
        let recipient = foreign_address();
        let request = CreatePsbtRequest::from_parts(&recipient.to_string(), 25_000, 2.0).unwrap();
        let result = wallet.create_bitcoin_transfer(&request).unwrap();
        let recipient_index = usize::try_from(result.intent.recipient_vout).unwrap();

        let mut mutations = Vec::new();
        let mut recipient_script = decode(&result.psbt);
        recipient_script.unsigned_tx.output[recipient_index].script_pubkey =
            wallet.peek_taproot_address(0).script_pubkey();
        mutations.push(recipient_script);

        let mut recipient_amount = decode(&result.psbt);
        recipient_amount.unsigned_tx.output[recipient_index].value = Amount::from_sat(24_999);
        mutations.push(recipient_amount);

        let mut fee = decode(&result.psbt);
        let change_index = (0..fee.unsigned_tx.output.len())
            .find(|index| *index != recipient_index)
            .unwrap();
        fee.unsigned_tx.output[change_index].value = Amount::from_sat(
            fee.unsigned_tx.output[change_index]
                .value
                .to_sat()
                .saturating_sub(1),
        );
        mutations.push(fee);

        let mut input = decode(&result.psbt);
        input.unsigned_tx.input[0].previous_output.vout = 1;
        mutations.push(input);

        for mutated in mutations {
            let encoded = encode(&mutated);
            let software_error = wallet
                .sign_bitcoin_transfer_psbt(&encoded, &result.intent, None)
                .unwrap_err();
            assert!(
                software_error.contains("Security Violation"),
                "{software_error}"
            );
            let hardware_error = wallet
                .prepare_external_bitcoin_transfer_signing_request(
                    &encoded,
                    &result.intent,
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
    fn inserted_external_output_is_rejected() {
        let mut wallet = funded_wallet();
        let recipient = foreign_address();
        let request = CreatePsbtRequest::from_parts(&recipient.to_string(), 25_000, 2.0).unwrap();
        let result = wallet.create_bitcoin_transfer(&request).unwrap();
        let mut psbt = decode(&result.psbt);
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: foreign_address().script_pubkey(),
        });
        psbt.outputs.push(Default::default());

        let error = wallet
            .sign_bitcoin_transfer_psbt(&encode(&psbt), &result.intent, None)
            .unwrap_err();
        assert!(error.contains("unapproved external output"), "{error}");
    }
}
