#[cfg(test)]
mod tests {
    use bitcoin::psbt::Input;
    use bitcoin::{OutPoint, Psbt, Transaction, TxIn, TxOut, Txid};
    use std::collections::HashSet;
    use std::str::FromStr;
    use zinc_core::ordinals::shield::{analyze_psbt_with_scope, audit_psbt, is_safe_to_spend};

    fn make_outpoint(i: u8) -> OutPoint {
        let hash = format!("{:064x}", i);
        OutPoint::new(Txid::from_str(&hash).unwrap(), 0)
    }

    fn build_test_psbt(inputs: Vec<(OutPoint, Option<TxOut>)>) -> Psbt {
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: Default::default(),
                    sequence: Default::default(),
                    witness: Default::default(),
                })
                .collect(),
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let psbt_inputs = inputs
            .into_iter()
            .map(|(_, maybe_utxo)| Input {
                witness_utxo: maybe_utxo,
                ..Input::default()
            })
            .collect();

        Psbt {
            unsigned_tx,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: psbt_inputs,
            outputs: vec![Default::default()],
        }
    }

    #[test]
    fn test_is_safe_to_spend() {
        let inscribed = make_outpoint(1);
        let safe = make_outpoint(2);

        let mut set = HashSet::new();
        set.insert(inscribed);

        assert!(!is_safe_to_spend(&inscribed, &set));
        assert!(is_safe_to_spend(&safe, &set));
    }

    #[test]
    fn test_audit_psbt_warn_only_for_unsafe() {
        let inscribed = make_outpoint(1);
        let mut set = HashSet::new();
        set.insert(inscribed);

        // Create a dummy PSBT with one inscribed input
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: inscribed,
                    script_sig: Default::default(),
                    sequence: Default::default(),
                    witness: Default::default(),
                }],
                output: vec![],
            },
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input {
                witness_utxo: Some(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
                ..Input::default()
            }],
            outputs: vec![],
        };

        // Create explicit map for audit_psbt
        let mut known_inscriptions = std::collections::HashMap::new();
        known_inscriptions.insert(
            (inscribed.txid, inscribed.vout),
            vec![("inscription-id".to_string(), 0)],
        );

        let result = audit_psbt(&psbt, &known_inscriptions, None, bitcoin::Network::Regtest);
        assert!(
            result.is_ok(),
            "warn-only policy should not reject risky PSBTs at audit stage"
        );
    }

    #[test]
    fn test_audit_psbt_scope_missing_metadata_fails() {
        let input0 = make_outpoint(10);
        let input1 = make_outpoint(11);
        let psbt = build_test_psbt(vec![
            (
                input0,
                Some(TxOut {
                    value: bitcoin::Amount::from_sat(2_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            ),
            (input1, None),
        ]);

        let scope = vec![1usize];
        let result = audit_psbt(
            &psbt,
            &std::collections::HashMap::new(),
            Some(scope.as_slice()),
            bitcoin::Network::Regtest,
        );

        let err = result.expect_err("scoped input missing metadata should fail");
        let message = err.to_string();
        assert!(
            message.contains("missing witness_utxo"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn test_audit_psbt_scope_ignores_unscoped_missing_metadata() {
        let input0 = make_outpoint(20);
        let input1 = make_outpoint(21);
        let psbt = build_test_psbt(vec![
            (input0, None),
            (
                input1,
                Some(TxOut {
                    value: bitcoin::Amount::from_sat(2_500),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            ),
        ]);

        let scope = vec![1usize];
        let result = audit_psbt(
            &psbt,
            &std::collections::HashMap::new(),
            Some(scope.as_slice()),
            bitcoin::Network::Regtest,
        );

        assert!(
            result.is_ok(),
            "scoped audit should not fail because unrelated unscoped input is missing metadata"
        );
    }

    #[test]
    fn test_audit_psbt_scope_out_of_bounds_fails() {
        let input0 = make_outpoint(30);
        let psbt = build_test_psbt(vec![(
            input0,
            Some(TxOut {
                value: bitcoin::Amount::from_sat(3_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }),
        )]);

        let scope = vec![5usize];
        let result = audit_psbt(
            &psbt,
            &std::collections::HashMap::new(),
            Some(scope.as_slice()),
            bitcoin::Network::Regtest,
        );

        let err = result.expect_err("out-of-bounds scope must fail");
        assert!(
            err.to_string().contains("out of bounds"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn test_analyze_psbt_with_scope_adds_partial_scope_warning() {
        let input0 = make_outpoint(40);
        let input1 = make_outpoint(41);
        let psbt = build_test_psbt(vec![
            (input0, None),
            (
                input1,
                Some(TxOut {
                    value: bitcoin::Amount::from_sat(5_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }),
            ),
        ]);

        let scope = vec![1usize];
        let analysis = analyze_psbt_with_scope(
            &psbt,
            &std::collections::HashMap::new(),
            Some(scope.as_slice()),
            bitcoin::Network::Regtest,
        )
        .expect("scoped analysis should succeed");

        assert!(
            analysis
                .warnings
                .iter()
                .any(|w| w.contains("Partial-scope audit")),
            "expected partial-scope warning, got: {:?}",
            analysis.warnings
        );
    }
}
