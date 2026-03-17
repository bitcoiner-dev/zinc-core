use crate::ordinals::shield::{analyze_psbt, WarningLevel};
use bitcoin::psbt::{Input, Psbt};
use bitcoin::transaction::Transaction;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use std::collections::HashMap;
use std::str::FromStr;

// Helper to create a dummy PSBT
fn create_dummy_psbt(inputs: &[(u64, Option<u64>)], outputs: &[u64]) -> Psbt {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let mut psbt_inputs = vec![];

    for (i, (value, _inscription_offset)) in inputs.iter().enumerate() {
        tx.input.push(bitcoin::TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                vout: u32::try_from(i).unwrap(),
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });

        let input = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: ScriptBuf::new(), // Dummy script
            }),
            ..Default::default()
        };
        psbt_inputs.push(input);
    }

    for value in outputs {
        tx.output.push(TxOut {
            value: Amount::from_sat(*value),
            script_pubkey: ScriptBuf::new(), // Dummy script
        });
    }

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs = psbt_inputs;
    psbt
}

#[test]
fn test_tight_squeeze_burn() {
    // Input: 10,000 sats. Inscription @ 9,999.
    // Output: 9,999 sats.
    // Fee: 1 sat.
    // Expectation: DANGER (Burned to fee).

    let inputs = vec![(10_000, Some(9_999))];
    let outputs = vec![9_999];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    // Build known inscriptions map
    let mut known_inscriptions = HashMap::new();
    // (txid, vout) -> (id, offset)
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[0].previous_output.txid, 0),
        vec![("Inscription 0".to_string(), 9_999_u64)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();

    assert_eq!(
        result.warning_level,
        WarningLevel::Danger,
        "Inscription at 9,999 should be burned if output is 9,999"
    );
    assert!(result
        .inscriptions_burned
        .contains(&"Inscription 0".to_string()));
}

#[test]
fn test_survivor_boundary() {
    // Input: 10,000 sats. Inscription @ 9,999.
    // Output: 10,000 sats.
    // Fee: 0 sats.
    // Expectation: SAFE.

    let inputs = vec![(10_000, Some(9_999))];
    let outputs = vec![10_000];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[0].previous_output.txid, 0),
        vec![("Inscription 0".to_string(), 9_999_u64)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();

    assert_eq!(result.warning_level, WarningLevel::Safe);
    assert!(result.inscriptions_burned.is_empty());
}

#[test]
fn test_multi_inscription_utxo() {
    // Input: 20,000 sats.
    // Inscr A @ 5,000. Inscr B @ 15,000.
    // Output 0: 10,000 sats.
    // Output 1: 10,000 sats.
    // Expectation: A -> Out 0, B -> Out 1.

    let inputs = vec![(20_000, None)];
    let outputs = vec![10_000, 10_000];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[0].previous_output.txid, 0),
        vec![
            ("Inscription 0".to_string(), 5_000),
            ("Inscription 1".to_string(), 15_000),
        ],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();

    // Verify A moved to Output 0
    let a_dest = result
        .inscription_destinations
        .get("Inscription 0")
        .unwrap();
    assert_eq!(a_dest.vout, Some(0));

    // Verify B moved to Output 1
    let b_dest = result
        .inscription_destinations
        .get("Inscription 1")
        .unwrap();
    assert_eq!(b_dest.vout, Some(1));
}

#[test]
fn test_mixed_inputs_order() {
    // Input 0: 5,000 (Clean)
    // Input 1: 5,000 (Inscr @ 0)
    // Output 0: 6,000
    // Expectation: Output 0 takes all Input 0 (5k) + 1k of Input 1.
    // Inscr @ 0 of Input 1 is the 5,001st sat overall.
    // Output 0 capacity is 6,000. So Inscr lands @ offset 5,000 of Output 0. SAFE.

    let inputs = vec![(5_000, None), (5_000, Some(0))];
    let outputs = vec![6_000];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[1].previous_output.txid, 1),
        vec![("Inscription 0".to_string(), 0)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();

    let dest = result
        .inscription_destinations
        .get("Inscription 0")
        .unwrap();
    assert_eq!(dest.vout, Some(0));
}

#[test]
fn test_blind_spot_missing_witness() {
    // Input 0: Value UNKNOWN (Missing witness_utxo)
    // Input 1: Inscription
    // Expectation: ERROR / CANNOT ANALYZE

    let mut psbt = create_dummy_psbt(&[(10_000, None), (10_000, Some(0))], &[20_000]);
    // Sabotage Input 0
    psbt.inputs[0].witness_utxo = None;

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[1].previous_output.txid, 1),
        vec![("Inscription 0".to_string(), 0)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest);
    assert!(result.is_err(), "Should fail if input value is unknown");
}

#[test]
fn test_burial_warning() {
    // Input 0: Inscr (546 sats)
    // Input 1: Payment (1 BTC = 100,000,000 sats)
    // Output 0: 100,000,546 (Consolidated)
    // Expectation: WARN (Merging inscr into large output)

    let inputs = vec![(546, Some(0)), (100_000_000, None)];
    let outputs = vec![100_000_546];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[0].previous_output.txid, 0),
        vec![("Inscription 0".to_string(), 0)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();
    assert_eq!(
        result.warning_level,
        WarningLevel::Warn,
        "Should warn when burying inscription"
    );
}

#[test]
fn test_random_offset_pointer() {
    // Input: 10,000. Inscription @ 3,500.
    // Output 0: 3,500.
    // Output 1: 6,500.
    // Expectation: Inscr is sat index 3,500 (3,501st sat).
    // Output 0 takes indices 0-3,499.
    // Output 1 takes indices 3,500-9,999.
    // Inscr lands at index 0 of Output 1.

    let inputs = vec![(10_000, Some(3_500))];
    let outputs = vec![3_500, 6_500];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let mut known_inscriptions = HashMap::new();
    known_inscriptions.insert(
        (psbt.unsigned_tx.input[0].previous_output.txid, 0),
        vec![("Inscription 0".to_string(), 3_500)],
    );

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest).unwrap();

    let dest = result
        .inscription_destinations
        .get("Inscription 0")
        .unwrap();
    assert_eq!(dest.vout, Some(1));
    assert_eq!(dest.offset, 0);
}

#[test]
fn test_split_transaction_safe() {
    // Current Split Flow:
    // Input 0: 100,000 sats (Clean BTC)
    // Output 0: 10,000 sats
    // Output 1: 10,000 sats
    // Output 2: 79,000 sats (Change)
    // Fee: 1,000 sats
    // Expectation: SAFE. No inscriptions.

    let inputs = vec![(100_000, None)];
    let outputs = vec![10_000, 10_000, 79_000];
    let psbt = create_dummy_psbt(&inputs, &outputs);

    let known_inscriptions = HashMap::new(); // Empty

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest)
        .expect("Should analyze successfully even if no inscriptions");

    assert_eq!(result.warning_level, WarningLevel::Safe);
    assert!(result.inscription_destinations.is_empty());
    assert!(result.inscriptions_burned.is_empty());
    assert_eq!(result.fee_sats, 1_000);
}

#[test]
fn test_missing_witness_utxo_error() {
    // Input 0: Value 100,000, but MISSING witness_utxo info in PSBT input
    // Expectation: Err(OrdError::RequestFailed("...missing witness_utxo..."))

    let mut psbt = create_dummy_psbt(&[(100_000, None)], &[99_000]);
    // Sabotage input
    psbt.inputs[0].witness_utxo = None;

    let known_inscriptions = HashMap::new();

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest);

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        crate::ordinals::error::OrdError::RequestFailed(msg) => {
            assert!(
                msg.contains("missing witness_utxo data"),
                "Error message should mention missing witness_utxo"
            );
        }
    }
}

#[test]
fn test_fallback_to_non_witness_utxo() {
    // Input 0: Missing witness_utxo, but HAS non_witness_utxo (Legacy/SegWit via PSBT fallback)
    // Expectation: SAFE (Should fallback and read value)

    let mut psbt = create_dummy_psbt(&[(10_000, None)], &[9_000]);

    // 1. Remove witness_utxo
    psbt.inputs[0].witness_utxo = None;

    // 2. Add non_witness_utxo (Legacy TxOut)
    let legacy_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![], // Inputs don't matter for this check usually, just the output at vout
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    psbt.inputs[0].non_witness_utxo = Some(legacy_tx);

    let known_inscriptions = HashMap::new();

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest)
        .expect("Should succeed by falling back to non_witness_utxo");

    assert_eq!(result.warning_level, WarningLevel::Safe);
    assert_eq!(result.fee_sats, 1_000);
}
#[test]
fn test_analyze_sighash_warning() {
    // Input 0: SIGHASH_NONE (Danger)
    // Expectation: DANGER + Warning in result

    let inputs = vec![(10_000, None)];
    let outputs = vec![9_000];
    let mut psbt = create_dummy_psbt(&inputs, &outputs);

    // Set dangerous SIGHASH (SIGHASH_NONE = 2)
    psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(2));

    let known_inscriptions: HashMap<(Txid, u32), Vec<(String, u64)>> = HashMap::new();

    let result = analyze_psbt(&psbt, &known_inscriptions, bitcoin::Network::Regtest)
        .expect("Analysis should succeed");

    assert_eq!(
        result.warning_level,
        WarningLevel::Danger,
        "SIGHASH_NONE should trigger Danger"
    );
    assert!(!result.warnings.is_empty(), "Should have warnings");
    assert!(
        result.warnings[0].contains("SIGHASH_NONE"),
        "Warning should mention SIGHASH_NONE"
    );
}
