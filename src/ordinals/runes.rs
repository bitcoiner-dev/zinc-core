//! Runes protocol support for the Ordinal Shield.
//!
//! Decodes the runestone (or cenotaph) carried by a transaction via the
//! canonical [`ordinals`] crate and simulates rune allocation across outputs,
//! mirroring ord's `RuneUpdater` semantics. All boundary types use
//! `"block:tx"` string rune IDs and decimal-string amounts so `u128` values
//! never reach JavaScript as lossy JSON numbers; `ordinals` crate types are
//! deliberately not re-exported (0.0.x versions never unify downstream).

use std::collections::BTreeMap;

use bitcoin::Transaction;
use ordinals::{Artifact, RuneId, Runestone, SpacedRune};
use serde::{Deserialize, Serialize};

/// Placeholder rune ID for the rune being etched by the analyzed transaction.
/// Its real ID is unknown until the transaction confirms.
pub const ETCHED_RUNE_PLACEHOLDER_ID: &str = "0:0";

/// A rune quantity attached to an input, output, or burn record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuneAmount {
    /// Rune ID in canonical `"block:tx"` form. `"0:0"` refers to the rune
    /// being etched by this transaction.
    pub rune_id: String,
    /// Raw amount in base (indivisible) units, serialized as a decimal string
    /// to preserve precision across the WASM/JS boundary.
    pub amount: String,
    /// Spaced rune name, when known from the wallet cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Divisibility, when known from the wallet cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divisibility: Option<u8>,
    /// Symbol, when known from the wallet cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

impl RuneAmount {
    pub(crate) fn new(rune_id: String, amount: u128) -> Self {
        Self {
            rune_id,
            amount: amount.to_string(),
            name: None,
            divisibility: None,
            symbol: None,
        }
    }
}

/// Summary of the etching declared by a runestone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuneEtchingSummary {
    /// Spaced rune name, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rune: Option<String>,
    /// Divisibility (number of decimal places), when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divisibility: Option<u8>,
    /// Symbol, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Premined amount in base units, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub premine: Option<String>,
    /// True when open-mint terms are declared.
    pub has_terms: bool,
}

/// Summary of the mint requested by a runestone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuneMintSummary {
    /// Rune being minted, `"block:tx"`.
    pub rune_id: String,
    /// Mint amount per the rune's cached terms (base units, decimal string).
    /// `None` when the terms are unknown offline — resolve via
    /// `resolveRuneInfo` and re-check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// Summary of the runestone (or cenotaph) carried by a transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuneActions {
    /// True when an OP_RETURN runestone payload is present.
    pub has_runestone: bool,
    /// True when the payload is a cenotaph: ALL input runes are burned.
    pub is_cenotaph: bool,
    /// Human-readable cenotaph flaw, when identifiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cenotaph_flaw: Option<String>,
    /// Etching declared by the runestone, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etching: Option<RuneEtchingSummary>,
    /// Mint requested by the runestone, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<RuneMintSummary>,
    /// Number of edicts in the runestone.
    pub edict_count: u32,
    /// Pointer output index for unallocated runes, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<u32>,
    /// Rune amounts this transaction would burn (cenotaph, allocation to the
    /// OP_RETURN output, or no eligible non-OP_RETURN output).
    #[serde(default)]
    pub burned: Vec<RuneAmount>,
    /// True when inputs carry runes but the transaction has no runestone: the
    /// protocol default moves ALL input runes to the first non-OP_RETURN
    /// output.
    #[serde(default)]
    pub default_transfer_without_runestone: bool,
    /// True when a mint amount could not be resolved offline; per-output
    /// amounts for the minted rune are omitted rather than guessed.
    #[serde(default)]
    pub mint_amount_unknown: bool,
}

/// Result of simulating rune flow for a transaction.
pub(crate) struct RuneFlowResult {
    /// Runestone summary plus burn records.
    pub actions: RuneActions,
    /// Simulated rune amounts per output, parallel to `tx.output`. Entries are
    /// `("block:tx", base units)`.
    pub output_runes: Vec<Vec<(String, u128)>>,
    /// Human-readable warnings to append to the analysis.
    pub warnings: Vec<String>,
    /// True when the flow burns runes (escalate to Danger).
    pub danger: bool,
}

fn spaced_rune_name(etching: &ordinals::Etching) -> Option<String> {
    etching.rune.map(|rune| {
        SpacedRune {
            rune,
            spacers: etching.spacers.unwrap_or_default(),
        }
        .to_string()
    })
}

/// Simulates rune allocation for `tx`, mirroring ord's `RuneUpdater`.
///
/// `input_holdings` is parallel to `tx.input` and carries each spent
/// outpoint's rune balances from the wallet cache. `mint_amount` is the
/// per-mint amount from the minted rune's cached terms, when known offline.
///
/// Rules encoded (see the runes specification):
/// - No runestone + input runes: everything moves to the first non-OP_RETURN
///   output ("default transfer"); burned if no such output exists.
/// - Cenotaph: all input runes are burned; a cenotaph mint is burned; a
///   cenotaph etching is unmintable.
/// - Edicts apply in order. `amount == 0` means "all remaining".
///   `output == tx.output.len()` distributes across all non-OP_RETURN outputs
///   (evenly for `amount == 0`, with the remainder going one unit at a time to
///   the leading outputs; otherwise `amount` per output until exhausted).
/// - Runes allocated to an OP_RETURN output are burned.
/// - Unallocated runes go to the pointer output when set, else the first
///   non-OP_RETURN output; if that target is missing they are burned.
/// - An unknown mint amount is never guessed: the minted rune's flows are
///   simulated from input holdings alone (a lower bound) and flagged.
pub(crate) fn simulate_rune_flow(
    tx: &Transaction,
    input_holdings: &[Vec<(RuneId, u128)>],
    mint_amount: Option<u128>,
) -> RuneFlowResult {
    let mut warnings = Vec::new();
    let mut danger = false;
    let mut actions = RuneActions::default();
    let mut output_runes: Vec<Vec<(String, u128)>> = vec![Vec::new(); tx.output.len()];

    // Aggregate input runes; BTreeMap keeps output ordering deterministic.
    let mut unallocated: BTreeMap<RuneId, u128> = BTreeMap::new();
    for holdings in input_holdings {
        for (id, amount) in holdings {
            let entry = unallocated.entry(*id).or_insert(0);
            *entry = entry.saturating_add(*amount);
        }
    }
    let has_input_runes = !unallocated.is_empty();

    let non_op_return_outputs: Vec<usize> = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| !output.script_pubkey.is_op_return())
        .map(|(vout, _)| vout)
        .collect();

    let artifact = Runestone::decipher(tx);

    let mut burned: BTreeMap<RuneId, u128> = BTreeMap::new();
    let burn = |map: &mut BTreeMap<RuneId, u128>, id: RuneId, amount: u128| {
        if amount > 0 {
            let entry = map.entry(id).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
    };

    match artifact {
        None => {
            if has_input_runes {
                actions.default_transfer_without_runestone = true;
                if let Some(&first) = non_op_return_outputs.first() {
                    warnings.push(format!(
                        "Inputs hold runes but the transaction has no runestone: all runes will move to output #{first}."
                    ));
                    for (id, amount) in &unallocated {
                        output_runes[first].push((id.to_string(), *amount));
                    }
                } else {
                    for (id, amount) in &unallocated {
                        burn(&mut burned, *id, *amount);
                    }
                }
                unallocated.clear();
            }
        }
        Some(Artifact::Cenotaph(cenotaph)) => {
            actions.has_runestone = true;
            actions.is_cenotaph = true;
            actions.cenotaph_flaw = cenotaph.flaw.map(|flaw| flaw.to_string());
            if let Some(mint) = cenotaph.mint {
                actions.mint = Some(RuneMintSummary {
                    rune_id: mint.to_string(),
                    amount: mint_amount.map(|amount| amount.to_string()),
                });
                match mint_amount {
                    Some(amount) => burn(&mut burned, mint, amount),
                    None => actions.mint_amount_unknown = true,
                }
            }
            if let Some(rune) = cenotaph.etching {
                actions.etching = Some(RuneEtchingSummary {
                    rune: Some(rune.to_string()),
                    ..RuneEtchingSummary::default()
                });
            }
            for (id, amount) in &unallocated {
                burn(&mut burned, *id, *amount);
            }
            unallocated.clear();
        }
        Some(Artifact::Runestone(runestone)) => {
            actions.has_runestone = true;
            actions.edict_count = u32::try_from(runestone.edicts.len()).unwrap_or(u32::MAX);
            actions.pointer = runestone.pointer;

            let etched_placeholder: RuneId = RuneId::default();
            if let Some(etching) = &runestone.etching {
                actions.etching = Some(RuneEtchingSummary {
                    rune: spaced_rune_name(etching),
                    divisibility: etching.divisibility,
                    symbol: etching.symbol.map(|symbol| symbol.to_string()),
                    premine: etching.premine.map(|premine| premine.to_string()),
                    has_terms: etching.terms.is_some(),
                });
                if let Some(premine) = etching.premine {
                    let entry = unallocated.entry(etched_placeholder).or_insert(0);
                    *entry = entry.saturating_add(premine);
                }
            }

            if let Some(mint) = runestone.mint {
                actions.mint = Some(RuneMintSummary {
                    rune_id: mint.to_string(),
                    amount: mint_amount.map(|amount| amount.to_string()),
                });
                match mint_amount {
                    Some(amount) => {
                        let entry = unallocated.entry(mint).or_insert(0);
                        *entry = entry.saturating_add(amount);
                    }
                    None => {
                        actions.mint_amount_unknown = true;
                        if unallocated.contains_key(&mint) {
                            warnings.push(format!(
                                "This transaction mints rune {mint}; the mint amount cannot be verified offline, so amounts shown for it are a lower bound."
                            ));
                        } else {
                            warnings.push(format!(
                                "This transaction mints rune {mint}; the mint amount cannot be verified offline."
                            ));
                        }
                    }
                }
            }

            for edict in &runestone.edicts {
                // An edict for the etched rune (0:0) without an etching is
                // skipped, matching ord.
                if edict.id == etched_placeholder && runestone.etching.is_none() {
                    continue;
                }
                let Some(balance) = unallocated.get_mut(&edict.id) else {
                    continue;
                };
                let output = edict.output as usize;

                if output == tx.output.len() {
                    // Distribute over all non-OP_RETURN outputs.
                    if edict.amount == 0 {
                        let count = non_op_return_outputs.len() as u128;
                        if count > 0 {
                            let share = *balance / count;
                            let remainder = (*balance % count) as usize;
                            for (position, vout) in non_op_return_outputs.iter().enumerate() {
                                let extra = u128::from(position < remainder);
                                let allocation = share + extra;
                                if allocation > 0 {
                                    output_runes[*vout].push((edict.id.to_string(), allocation));
                                }
                            }
                            *balance = 0;
                        }
                    } else {
                        for vout in &non_op_return_outputs {
                            if *balance == 0 {
                                break;
                            }
                            let allocation = edict.amount.min(*balance);
                            output_runes[*vout].push((edict.id.to_string(), allocation));
                            *balance -= allocation;
                        }
                    }
                } else {
                    let allocation = if edict.amount == 0 {
                        *balance
                    } else {
                        edict.amount.min(*balance)
                    };
                    if allocation > 0 {
                        output_runes[output].push((edict.id.to_string(), allocation));
                        *balance -= allocation;
                    }
                }
            }

            // Remainder: pointer output when set, else first non-OP_RETURN.
            let remainder_target = runestone
                .pointer
                .map(|pointer| pointer as usize)
                .or_else(|| non_op_return_outputs.first().copied());
            for (id, amount) in &unallocated {
                if *amount == 0 {
                    continue;
                }
                match remainder_target {
                    Some(vout) if vout < tx.output.len() => {
                        output_runes[vout].push((id.to_string(), *amount));
                    }
                    _ => burn(&mut burned, *id, *amount),
                }
            }
            unallocated.clear();
        }
    }

    // Coalesce duplicate rune entries per output, then burn anything that
    // landed on an OP_RETURN output.
    for (vout, entries) in output_runes.iter_mut().enumerate() {
        if entries.is_empty() {
            continue;
        }
        let mut merged: BTreeMap<String, u128> = BTreeMap::new();
        for (id, amount) in entries.drain(..) {
            let entry = merged.entry(id).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
        if tx.output[vout].script_pubkey.is_op_return() {
            for (id, amount) in merged {
                if let Ok(rune_id) = id.parse::<RuneId>() {
                    burn(&mut burned, rune_id, amount);
                }
            }
        } else {
            entries.extend(merged);
        }
    }

    if actions.is_cenotaph && (has_input_runes || actions.mint.is_some()) {
        let flaw = actions
            .cenotaph_flaw
            .clone()
            .unwrap_or_else(|| "unknown flaw".to_string());
        warnings.push(format!(
            "This transaction is a cenotaph: ALL runes on its inputs will be permanently burned (flaw: {flaw})."
        ));
    }

    for (id, amount) in &burned {
        warnings.push(format!("{amount} of rune {id} will be burned."));
    }
    if !burned.is_empty() || (actions.is_cenotaph && has_input_runes) {
        danger = true;
    }

    actions.burned = burned
        .into_iter()
        .map(|(id, amount)| RuneAmount::new(id.to_string(), amount))
        .collect();

    RuneFlowResult {
        actions,
        output_runes,
        warnings,
        danger,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn,
        TxOut, Witness,
    };
    use ordinals::{Edict, Etching, Terms};

    fn rune_id(block: u64, tx: u32) -> RuneId {
        RuneId::new(block, tx).unwrap()
    }

    fn tx_with_outputs(runestone: Option<&Runestone>, output_count: usize) -> Transaction {
        let mut output: Vec<TxOut> = (0..output_count)
            .map(|_| TxOut {
                value: Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            })
            .collect();
        if let Some(runestone) = runestone {
            output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: runestone.encipher(),
            });
        }
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        }
    }

    fn amounts(entries: &[(String, u128)]) -> Vec<(String, u128)> {
        entries.to_vec()
    }

    #[test]
    fn no_runestone_defaults_all_input_runes_to_first_output() {
        let tx = tx_with_outputs(None, 2);
        let holdings = vec![vec![(rune_id(840_000, 3), 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert!(result.actions.default_transfer_without_runestone);
        assert!(!result.actions.has_runestone);
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 100)]);
        assert!(result.output_runes[1].is_empty());
        assert!(result.actions.burned.is_empty());
        assert!(!result.danger);
    }

    #[test]
    fn no_runestone_and_no_eligible_output_burns() {
        // Only output is an OP_RETURN (a bare runestone-less data output).
        let mut tx = tx_with_outputs(None, 0);
        tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return([]),
        });
        let holdings = vec![vec![(rune_id(840_000, 3), 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert_eq!(result.actions.burned.len(), 1);
        assert_eq!(result.actions.burned[0].amount, "100");
        assert!(result.danger);
    }

    #[test]
    fn cenotaph_burns_all_input_runes() {
        // An unrecognized even tag produces a cenotaph.
        let script = ScriptBuf::from_bytes(
            [
                bitcoin::opcodes::all::OP_RETURN.to_u8(),
                bitcoin::opcodes::all::OP_PUSHNUM_13.to_u8(),
                0x02,
                126, // unrecognized even tag
                0,
            ]
            .to_vec(),
        );
        let mut tx = tx_with_outputs(None, 1);
        tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: script,
        });
        let holdings = vec![vec![(rune_id(840_000, 3), 250u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert!(result.actions.is_cenotaph);
        assert!(result.actions.cenotaph_flaw.is_some());
        assert_eq!(result.actions.burned.len(), 1);
        assert_eq!(result.actions.burned[0].amount, "250");
        assert!(result.danger);
        assert!(result.output_runes.iter().all(Vec::is_empty));
    }

    #[test]
    fn edict_moves_exact_amount_and_remainder_follows_pointer_default() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            edicts: vec![Edict { id, amount: 30, output: 1 }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        // 30 to output 1; remainder 70 to first non-OP_RETURN output (0).
        assert_eq!(amounts(&result.output_runes[1]), vec![("840000:3".to_string(), 30)]);
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 70)]);
        assert!(result.actions.burned.is_empty());
    }

    #[test]
    fn edict_amount_zero_moves_all_remaining() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            edicts: vec![Edict { id, amount: 0, output: 1 }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert_eq!(amounts(&result.output_runes[1]), vec![("840000:3".to_string(), 100)]);
        assert!(result.output_runes[0].is_empty());
    }

    #[test]
    fn edict_output_equals_len_splits_evenly_with_remainder_to_leading() {
        let id = rune_id(840_000, 3);
        // output == tx.output.len() (3 = 2 pay outputs + OP_RETURN).
        let runestone = Runestone {
            edicts: vec![Edict { id, amount: 0, output: 3 }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 101u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        // 101 over 2 outputs: 51 to the first, 50 to the second.
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 51)]);
        assert_eq!(amounts(&result.output_runes[1]), vec![("840000:3".to_string(), 50)]);
    }

    #[test]
    fn edict_output_equals_len_with_amount_gives_each_until_exhausted() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            edicts: vec![Edict { id, amount: 60, output: 3 }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        // 60 to output 0, remaining 40 to output 1.
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 60)]);
        assert_eq!(amounts(&result.output_runes[1]), vec![("840000:3".to_string(), 40)]);
    }

    #[test]
    fn edict_to_op_return_burns() {
        let id = rune_id(840_000, 3);
        // The runestone output is appended last: index 1 (1 pay output).
        let runestone = Runestone {
            edicts: vec![Edict { id, amount: 40, output: 1 }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 1);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert_eq!(result.actions.burned.len(), 1);
        assert_eq!(result.actions.burned[0].amount, "40");
        // Remainder 60 to first non-OP_RETURN output.
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 60)]);
        assert!(result.danger);
    }

    #[test]
    fn pointer_routes_remainder() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            pointer: Some(1),
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert!(result.output_runes[0].is_empty());
        assert_eq!(amounts(&result.output_runes[1]), vec![("840000:3".to_string(), 100)]);
    }

    #[test]
    fn etching_premine_allocates_under_placeholder_id() {
        let runestone = Runestone {
            etching: Some(Etching {
                premine: Some(1_000),
                rune: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap()),
                terms: Some(Terms {
                    amount: Some(10),
                    cap: Some(100),
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
        let tx = tx_with_outputs(Some(&runestone), 1);
        let result = simulate_rune_flow(&tx, &[Vec::new()], None);
        let etching = result.actions.etching.as_ref().unwrap();
        assert!(etching.has_terms);
        assert_eq!(etching.premine.as_deref(), Some("1000"));
        assert_eq!(
            amounts(&result.output_runes[0]),
            vec![(ETCHED_RUNE_PLACEHOLDER_ID.to_string(), 1_000)]
        );
    }

    #[test]
    fn edict_for_placeholder_without_etching_is_skipped() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            edicts: vec![Edict {
                id: RuneId::default(),
                amount: 0,
                output: 0,
            }],
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 2);
        let holdings = vec![vec![(id, 100u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        // The 0:0 edict is skipped; input runes ride the remainder path.
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 100)]);
    }

    #[test]
    fn mint_with_known_amount_allocates() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            mint: Some(id),
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 1);
        let result = simulate_rune_flow(&tx, &[Vec::new()], Some(500));
        assert_eq!(result.actions.mint.as_ref().unwrap().amount.as_deref(), Some("500"));
        assert!(!result.actions.mint_amount_unknown);
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 500)]);
    }

    #[test]
    fn mint_with_unknown_amount_is_flagged_not_guessed() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone {
            mint: Some(id),
            ..Runestone::default()
        };
        let tx = tx_with_outputs(Some(&runestone), 1);
        let result = simulate_rune_flow(&tx, &[Vec::new()], None);
        assert!(result.actions.mint_amount_unknown);
        assert!(result.actions.mint.as_ref().unwrap().amount.is_none());
        assert!(result.output_runes[0].is_empty());
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("cannot be verified offline")));
    }

    #[test]
    fn multi_input_same_rune_aggregates() {
        let id = rune_id(840_000, 3);
        let runestone = Runestone::default();
        let tx = tx_with_outputs(Some(&runestone), 1);
        let holdings = vec![vec![(id, 60u128)], vec![(id, 40u128)]];
        let result = simulate_rune_flow(&tx, &holdings, None);
        assert_eq!(amounts(&result.output_runes[0]), vec![("840000:3".to_string(), 100)]);
    }
}
