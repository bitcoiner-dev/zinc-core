//! End-to-end Ordinal Shield rune analysis over fixture PSBTs whose
//! runestones are built with the canonical encoder (`Runestone::encipher`).

use bitcoin::psbt::Input;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use ordinals::{Edict, Etching, RuneId, Runestone, Terms};
use std::collections::HashMap;
use std::str::FromStr;
use zinc_core::ordinals::shield::{
    analyze_psbt, analyze_psbt_with_context, KnownRunes, ShieldContext, WarningLevel,
};

const DOG: &str = "840000:3";

fn rune_id() -> RuneId {
    RuneId::new(840_000, 3).unwrap()
}

fn outpoint(i: u8) -> OutPoint {
    let hash = format!("{i:064x}");
    OutPoint::new(Txid::from_str(&hash).unwrap(), 0)
}

fn p2tr_script(seed: u8) -> ScriptBuf {
    // A syntactically valid P2TR script (OP_1 <32 bytes>); fine for analysis.
    let mut bytes = vec![0x51, 0x20];
    bytes.extend(std::iter::repeat_n(seed, 32));
    ScriptBuf::from_bytes(bytes)
}

struct FixtureOutput {
    value: u64,
    script: ScriptBuf,
}

fn build_psbt(input_outpoints: &[OutPoint], outputs: Vec<FixtureOutput>) -> Psbt {
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: input_outpoints
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::default(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(o.value),
                script_pubkey: o.script.clone(),
            })
            .collect(),
    };
    let output_count = unsigned_tx.output.len();

    Psbt {
        unsigned_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: input_outpoints
            .iter()
            .enumerate()
            .map(|(index, _)| Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: p2tr_script(u8::try_from(index).unwrap() + 1),
                }),
                ..Input::default()
            })
            .collect(),
        outputs: vec![Default::default(); output_count],
    }
}

fn known_runes_for(op: OutPoint, amount: u128) -> KnownRunes {
    let mut map = KnownRunes::new();
    map.insert((op.txid, op.vout), vec![(DOG.to_string(), amount)]);
    map
}

fn analyze(
    psbt: &Psbt,
    known_runes: &KnownRunes,
    mint_terms: &HashMap<String, u128>,
    input_scope: Option<&[usize]>,
) -> zinc_core::ordinals::shield::AnalysisResult {
    let known_inscriptions = HashMap::new();
    let ctx = ShieldContext {
        known_inscriptions: &known_inscriptions,
        known_runes,
        input_scope,
        network: bitcoin::Network::Bitcoin,
        mint_terms,
        assets_verified: true,
    };
    analyze_psbt_with_context(psbt, &ctx).expect("analysis should succeed")
}

fn runestone_output(runestone: &Runestone) -> FixtureOutput {
    FixtureOutput {
        value: 0,
        script: runestone.encipher(),
    }
}

#[test]
fn rune_transfer_with_edict_annotates_outputs() {
    let op = outpoint(1);
    let runestone = Runestone {
        edicts: vec![Edict {
            id: rune_id(),
            amount: 1_200,
            output: 0,
        }],
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[op],
        vec![
            FixtureOutput { value: 546, script: p2tr_script(0xaa) },
            FixtureOutput { value: 9_000, script: p2tr_script(0xbb) },
            runestone_output(&runestone),
        ],
    );
    let analysis = analyze(&psbt, &known_runes_for(op, 1_200), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Safe);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert!(actions.has_runestone);
    assert_eq!(actions.edict_count, 1);
    assert!(actions.burned.is_empty());
    assert_eq!(analysis.inputs[0].runes.len(), 1);
    assert_eq!(analysis.inputs[0].runes[0].amount, "1200");
    assert_eq!(analysis.outputs[0].runes.len(), 1);
    assert_eq!(analysis.outputs[0].runes[0].rune_id, DOG);
    assert_eq!(analysis.outputs[0].runes[0].amount, "1200");
    assert!(analysis.outputs[1].runes.is_empty());
    assert!(analysis.outputs[2].is_op_return);
    assert!(analysis.fee_rate_sat_vb.is_some());
}

#[test]
fn no_runestone_default_transfer_warns() {
    let op = outpoint(2);
    let psbt = build_psbt(
        &[op],
        vec![FixtureOutput { value: 9_500, script: p2tr_script(0xaa) }],
    );
    let analysis = analyze(&psbt, &known_runes_for(op, 500), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Warn);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert!(actions.default_transfer_without_runestone);
    assert_eq!(analysis.outputs[0].runes[0].amount, "500");
    assert!(analysis
        .warnings
        .iter()
        .any(|w| w.contains("no runestone")));
}

#[test]
fn cenotaph_burns_and_escalates_to_danger() {
    let op = outpoint(3);
    // Handcrafted OP_RETURN OP_13 payload with an unrecognized even tag.
    let script = ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x02, 126, 0]);
    let psbt = build_psbt(
        &[op],
        vec![
            FixtureOutput { value: 9_000, script: p2tr_script(0xaa) },
            FixtureOutput { value: 0, script },
        ],
    );
    let analysis = analyze(&psbt, &known_runes_for(op, 777), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Danger);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert!(actions.is_cenotaph);
    assert_eq!(actions.burned.len(), 1);
    assert_eq!(actions.burned[0].amount, "777");
    assert!(analysis.outputs.iter().all(|o| o.runes.is_empty()));
}

#[test]
fn edict_to_op_return_burns_and_escalates() {
    let op = outpoint(4);
    let runestone = Runestone {
        edicts: vec![Edict {
            id: rune_id(),
            amount: 40,
            output: 1, // the runestone output itself
        }],
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[op],
        vec![
            FixtureOutput { value: 9_000, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let analysis = analyze(&psbt, &known_runes_for(op, 100), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Danger);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert_eq!(actions.burned[0].amount, "40");
    assert_eq!(analysis.outputs[0].runes[0].amount, "60"); // remainder
}

#[test]
fn mint_with_cached_terms_allocates_and_stays_safe() {
    let runestone = Runestone {
        mint: Some(rune_id()),
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[outpoint(5)],
        vec![
            FixtureOutput { value: 546, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let mut terms = HashMap::new();
    terms.insert(DOG.to_string(), 500u128);
    let analysis = analyze(&psbt, &KnownRunes::new(), &terms, None);

    assert_eq!(analysis.warning_level, WarningLevel::Safe);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert_eq!(actions.mint.as_ref().unwrap().amount.as_deref(), Some("500"));
    assert!(!actions.mint_amount_unknown);
    assert_eq!(analysis.outputs[0].runes[0].amount, "500");
}

#[test]
fn mint_without_terms_is_flagged_and_warns() {
    let runestone = Runestone {
        mint: Some(rune_id()),
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[outpoint(6)],
        vec![
            FixtureOutput { value: 546, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let analysis = analyze(&psbt, &KnownRunes::new(), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Warn);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    assert!(actions.mint_amount_unknown);
    assert!(actions.mint.as_ref().unwrap().amount.is_none());
    assert!(analysis.outputs[0].runes.is_empty());
}

#[test]
fn etching_with_premine_allocates_placeholder_and_warns() {
    let runestone = Runestone {
        etching: Some(Etching {
            premine: Some(21_000),
            rune: Some("ZINCZINCZINCZINC".parse().unwrap()),
            terms: Some(Terms {
                amount: Some(100),
                cap: Some(1_000),
                height: (None, None),
                offset: (None, None),
            }),
            ..Etching::default()
        }),
        edicts: vec![Edict {
            id: RuneId::default(),
            amount: 0,
            output: 0,
        }],
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[outpoint(7)],
        vec![
            FixtureOutput { value: 546, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let analysis = analyze(&psbt, &KnownRunes::new(), &HashMap::new(), None);

    assert_eq!(analysis.warning_level, WarningLevel::Warn);
    let actions = analysis.rune_actions.as_ref().expect("rune actions");
    let etching = actions.etching.as_ref().expect("etching summary");
    assert!(etching.has_terms);
    assert_eq!(etching.premine.as_deref(), Some("21000"));
    assert_eq!(analysis.outputs[0].runes[0].rune_id, "0:0");
    assert_eq!(analysis.outputs[0].runes[0].amount, "21000");
}

#[test]
fn mixed_inscription_and_rune_input_reports_both() {
    let op = outpoint(8);
    let runestone = Runestone {
        edicts: vec![Edict {
            id: rune_id(),
            amount: 0,
            output: 0,
        }],
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[op],
        vec![
            FixtureOutput { value: 10_000, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let mut known_inscriptions: HashMap<(Txid, u32), Vec<(String, u64)>> = HashMap::new();
    known_inscriptions.insert((op.txid, op.vout), vec![("insc-1".to_string(), 0)]);
    let known_runes = known_runes_for(op, 42);
    let mut terms = HashMap::new();
    terms.insert(DOG.to_string(), 0u128);
    let ctx = ShieldContext {
        known_inscriptions: &known_inscriptions,
        known_runes: &known_runes,
        input_scope: None,
        network: bitcoin::Network::Bitcoin,
        mint_terms: &terms,
        assets_verified: true,
    };
    let analysis = analyze_psbt_with_context(&psbt, &ctx).expect("analysis");

    assert!(analysis.inscription_destinations.contains_key("insc-1"));
    assert_eq!(analysis.inputs[0].inscriptions, vec!["insc-1".to_string()]);
    assert_eq!(analysis.inputs[0].runes[0].amount, "42");
    assert_eq!(analysis.outputs[0].runes[0].amount, "42");
}

#[test]
fn partial_scope_skips_rune_simulation_and_warns() {
    let op = outpoint(9);
    let psbt = build_psbt(
        &[op, outpoint(10)],
        vec![FixtureOutput { value: 15_000, script: p2tr_script(0xaa) }],
    );
    let analysis = analyze(
        &psbt,
        &known_runes_for(op, 500),
        &HashMap::new(),
        Some(&[0]),
    );

    assert!(analysis.rune_actions.is_none());
    assert!(analysis.outputs[0].runes.is_empty());
    assert!(analysis
        .warnings
        .iter()
        .any(|w| w.contains("partial-scope")));
}

#[test]
fn dust_outputs_are_flagged() {
    let psbt = build_psbt(
        &[outpoint(11)],
        vec![
            FixtureOutput { value: 100, script: p2tr_script(0xaa) },
            FixtureOutput { value: 9_000, script: p2tr_script(0xbb) },
        ],
    );
    let analysis = analyze(&psbt, &KnownRunes::new(), &HashMap::new(), None);

    assert!(analysis.outputs[0].is_dust);
    assert!(!analysis.outputs[1].is_dust);
}

#[test]
fn legacy_entry_point_stays_rune_blind() {
    let op = outpoint(12);
    let runestone = Runestone {
        edicts: vec![Edict {
            id: rune_id(),
            amount: 0,
            output: 0,
        }],
        ..Runestone::default()
    };
    let psbt = build_psbt(
        &[op],
        vec![
            FixtureOutput { value: 546, script: p2tr_script(0xaa) },
            runestone_output(&runestone),
        ],
    );
    let analysis = analyze_psbt(&psbt, &HashMap::new(), bitcoin::Network::Bitcoin)
        .expect("legacy analysis");

    assert!(analysis.rune_actions.is_none());
    assert!(analysis.fee_rate_sat_vb.is_none());
    assert!(analysis.outputs.iter().all(|o| o.runes.is_empty()));
    // The additive flags still populate in the core loop.
    assert!(analysis.outputs[1].is_op_return);
}
