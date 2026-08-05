#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::external_signing::{
        check_external_signer_compatibility, classify_external_signing_output,
        derive_external_signing_requirements, CapabilityRejectionCodeV1,
        ExternalSignerCapabilitiesV1, ExternalSignerLimitsV1, ExternalSigningInputTypeV1,
        ExternalSigningOutputTypeV1, EXTERNAL_SIGNING_SCHEMA_V1,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };
    use std::collections::BTreeSet;

    fn p2tr(tag: u8) -> ScriptBuf {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend([tag; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    fn p2wpkh(tag: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend([tag; 20]);
        ScriptBuf::from_bytes(bytes)
    }

    fn psbt(input_scripts: &[ScriptBuf], output_scripts: &[ScriptBuf]) -> Psbt {
        let inputs = input_scripts
            .iter()
            .enumerate()
            .map(|(index, _)| TxIn {
                previous_output: OutPoint::new(
                    Txid::from_byte_array([u8::try_from(index + 1).unwrap(); 32]),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        let outputs = output_scripts
            .iter()
            .cloned()
            .map(|script_pubkey| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey,
            })
            .collect();
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        })
        .unwrap();
        for (input, script_pubkey) in psbt.inputs.iter_mut().zip(input_scripts) {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: script_pubkey.clone(),
            });
        }
        psbt
    }

    fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
        items.into_iter().collect()
    }

    #[test]
    fn exact_output_classifier_distinguishes_runestones_from_push_data() {
        let runestone = ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x01, 0x00]);
        let push_data = ScriptBuf::from_bytes(vec![0x6a, 0x02, 0xaa, 0xbb]);
        let arbitrary_op_return = ScriptBuf::from_bytes(vec![0x6a, 0x76]);

        assert_eq!(
            classify_external_signing_output(runestone.as_script()),
            ExternalSigningOutputTypeV1::Runestone
        );
        assert_eq!(
            classify_external_signing_output(push_data.as_script()),
            ExternalSigningOutputTypeV1::OpReturnPushData
        );
        assert_eq!(
            classify_external_signing_output(arbitrary_op_return.as_script()),
            ExternalSigningOutputTypeV1::ArbitraryScript
        );
    }

    #[test]
    fn derives_requirements_from_exact_psbt_and_signing_scope() {
        let runestone = ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x01, 0x00]);
        let psbt = psbt(&[p2tr(1), p2wpkh(2)], &[p2tr(3), runestone]);

        let requirements = derive_external_signing_requirements(&psbt, Some(&[0])).unwrap();

        assert_eq!(requirements.schema_version, EXTERNAL_SIGNING_SCHEMA_V1);
        assert_eq!(requirements.required_input_indices, vec![0]);
        assert_eq!(
            requirements.input_types,
            set([ExternalSigningInputTypeV1::P2trKeyPath])
        );
        assert_eq!(requirements.sighash_types, set([0]));
        assert_eq!(
            requirements.output_types,
            set([
                ExternalSigningOutputTypeV1::P2tr,
                ExternalSigningOutputTypeV1::Runestone,
            ])
        );
        assert!(requirements.has_external_inputs);
        assert!(requirements.requires_selective_signing);
    }

    #[test]
    fn unsupported_runestone_is_a_typed_deny_before_device_dispatch() {
        let runestone = ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x01, 0x00]);
        let psbt = psbt(&[p2tr(1)], &[p2tr(2), runestone]);
        let requirements = derive_external_signing_requirements(&psbt, None).unwrap();
        let mut capabilities = ExternalSignerCapabilitiesV1::deny_all("test:stock-firmware");
        capabilities.supported_input_types = set([ExternalSigningInputTypeV1::P2trKeyPath]);
        capabilities.supported_output_types = set([
            ExternalSigningOutputTypeV1::P2tr,
            ExternalSigningOutputTypeV1::OpReturnPushData,
        ]);
        capabilities.supported_sighash_types = set([0]);

        let report = check_external_signer_compatibility(&requirements, &capabilities);

        assert!(!report.compatible);
        assert_eq!(report.rejections.len(), 1);
        assert_eq!(
            report.rejections[0].code,
            CapabilityRejectionCodeV1::CapabilityUnsupported
        );
        assert_eq!(report.rejections[0].capability, "output.runestone");
        assert!(report.rejections[0].message.contains("cannot represent"));
    }

    #[test]
    fn matcher_collects_scope_and_device_limit_rejections() {
        let psbt = psbt(&[p2tr(1), p2tr(2)], &[p2tr(3)]);
        let requirements = derive_external_signing_requirements(&psbt, Some(&[0])).unwrap();
        let mut capabilities = ExternalSignerCapabilitiesV1::deny_all("test:limited");
        capabilities.supported_input_types = set([ExternalSigningInputTypeV1::P2trKeyPath]);
        capabilities.supported_output_types = set([ExternalSigningOutputTypeV1::P2tr]);
        capabilities.supported_sighash_types = set([0]);
        capabilities.limits = ExternalSignerLimitsV1 {
            max_inputs: Some(1),
            max_outputs: None,
        };

        let report = check_external_signer_compatibility(&requirements, &capabilities);
        let keys = report
            .rejections
            .iter()
            .map(|rejection| rejection.capability.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            keys,
            set([
                "limits.inputs",
                "signing.selective_inputs",
                "transaction.external_inputs",
            ])
        );
        assert!(report
            .rejections
            .iter()
            .any(|rejection| rejection.code == CapabilityRejectionCodeV1::DeviceLimitExceeded));
    }

    #[test]
    fn capability_json_is_versioned_and_uses_stable_names() {
        let mut capabilities = ExternalSignerCapabilitiesV1::deny_all("vendor:model:firmware");
        capabilities.supported_input_types = set([ExternalSigningInputTypeV1::P2trKeyPath]);
        capabilities.supported_output_types = set([ExternalSigningOutputTypeV1::Runestone]);
        let value = serde_json::to_value(capabilities).unwrap();

        assert_eq!(value["schemaVersion"], EXTERNAL_SIGNING_SCHEMA_V1);
        assert_eq!(value["supportedInputTypes"][0], "p2tr_key_path");
        assert_eq!(value["supportedOutputTypes"][0], "runestone");
    }
}
