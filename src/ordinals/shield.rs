use crate::ordinals::error::OrdError;
use bitcoin::{OutPoint, Psbt, Txid};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const LOG_TARGET_SHIELD: &str = "zinc_core::ordinals::shield";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Risk classification returned by Ordinal Shield analysis.
pub enum WarningLevel {
    /// No suspicious inscription movement detected.
    Safe,
    /// Potentially risky conditions detected; user review recommended.
    Warn,
    /// High-risk conditions detected (for example burns or unsafe sighash).
    Danger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Destination mapping for an inscription after simulated PSBT sat flow.
pub struct InscriptionDestination {
    /// Destination output index, or `None` when inscription is burned to fee.
    pub vout: Option<u32>, // None means fee/burned
    /// Offset within destination output where inscription lands.
    pub offset: u64, // Offset within that output
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Input-side metadata exposed for Shield analysis UI.
pub struct InputInfo {
    /// Previous transaction id being spent.
    pub txid: String,
    /// Previous output index being spent.
    pub vout: u32,
    /// Input value in sats.
    pub value: u64,
    /// Hex-encoded scriptPubKey.
    pub script_pubkey: String,
    /// Decoded address when script can be mapped on provided network.
    pub address: Option<String>,
    /// Whether input belongs to current wallet context when known.
    ///
    /// This is `false` when ownership context is not provided.
    pub is_mine: bool,
    /// Inscription ids known on this input.
    pub inscriptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Output-side metadata exposed for Shield analysis UI.
pub struct OutputInfo {
    /// Output index in unsigned transaction.
    pub vout: u32,
    /// Output value in sats.
    pub value: u64,
    /// Hex-encoded scriptPubKey.
    pub script_pubkey: String,
    /// Decoded address when script can be mapped on provided network.
    pub address: Option<String>,
    /// Whether output is wallet change when known.
    ///
    /// This is `false` when change classification is not provided.
    pub is_change: bool,
    /// Inscription ids mapped into this output.
    pub inscriptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Full Ordinal Shield analysis report for a candidate PSBT.
pub struct AnalysisResult {
    /// Overall risk level.
    pub warning_level: WarningLevel,
    /// Inscriptions that would be burned as fee.
    pub inscriptions_burned: Vec<String>, // List of inscription IDs
    /// Destination map keyed by inscription id.
    pub inscription_destinations: HashMap<String, InscriptionDestination>,
    /// Computed mining fee in sats.
    pub fee_sats: u64,
    #[serde(default)]
    /// Human-readable warnings explaining risky conditions.
    pub warnings: Vec<String>, // Human readable warnings (e.g. SIGHASH types)
    #[serde(default)]
    /// Input metadata used for analysis explainability.
    pub inputs: Vec<InputInfo>,
    #[serde(default)]
    /// Output metadata used for analysis explainability.
    pub outputs: Vec<OutputInfo>,
}

/// Checks if a UTXO is safe to spend (not inscribed).
/// Returns true if the UTXO is NOT in the inscribed set.
/// Returns false if it IS inscribed (unsafe).
pub fn is_safe_to_spend(outpoint: &OutPoint, inscribed_utxos: &HashSet<OutPoint>) -> bool {
    !inscribed_utxos.contains(outpoint)
}

/// Analyze full PSBT sat flow and inscription movement.
pub fn analyze_psbt(
    psbt: &Psbt,
    known_inscriptions: &HashMap<(Txid, u32), Vec<(String, u64)>>,
    network: bitcoin::Network,
) -> Result<AnalysisResult, OrdError> {
    analyze_psbt_with_scope(psbt, known_inscriptions, None, network)
}

fn normalize_input_scope(
    input_scope: Option<&[usize]>,
    input_count: usize,
) -> Result<Option<Vec<usize>>, OrdError> {
    let Some(scope) = input_scope else {
        return Ok(None);
    };

    if scope.is_empty() {
        return Err(OrdError::RequestFailed(
            "Ordinal Shield Error: input scope cannot be empty.".to_string(),
        ));
    }

    let mut deduped = scope.to_vec();
    deduped.sort_unstable();
    deduped.dedup();

    if let Some(index) = deduped.iter().find(|&&idx| idx >= input_count) {
        return Err(OrdError::RequestFailed(format!(
            "Ordinal Shield Error: input scope index {} is out of bounds ({} inputs).",
            index, input_count
        )));
    }

    Ok(Some(deduped))
}

fn input_value_for_audit(
    psbt: &Psbt,
    index: usize,
    require_metadata: bool,
) -> Result<Option<u64>, OrdError> {
    if let Some(txout) = psbt.inputs[index].witness_utxo.as_ref() {
        return Ok(Some(txout.value.to_sat()));
    }

    if let Some(prev_tx) = psbt.inputs[index].non_witness_utxo.as_ref() {
        let vout_idx = psbt.unsigned_tx.input[index].previous_output.vout as usize;
        return prev_tx
            .output
            .get(vout_idx)
            .map(|output| Some(output.value.to_sat()))
            .ok_or_else(|| {
                OrdError::RequestFailed(format!(
                    "Ordinal Shield Error: Input #{} non_witness_utxo found but vout index {} invalid.",
                    index, vout_idx
                ))
            });
    }

    if require_metadata {
        return Err(OrdError::RequestFailed(format!(
            "Ordinal Shield Error: Input #{} missing witness_utxo data. Cannot safely analyze.",
            index
        )));
    }

    Ok(None)
}

/// Analyze PSBT sat flow with optional input scope for partial-signing flows.
///
/// When `input_scope` is provided, strict metadata checks are applied only to the
/// scoped inputs. Unscoped inputs with missing metadata are treated as unknown and
/// can reduce precision; in that case a warning is injected into the analysis.
pub fn analyze_psbt_with_scope(
    psbt: &Psbt,
    known_inscriptions: &HashMap<(Txid, u32), Vec<(String, u64)>>,
    input_scope: Option<&[usize]>,
    network: bitcoin::Network,
) -> Result<AnalysisResult, OrdError> {
    let normalized_scope = normalize_input_scope(input_scope, psbt.inputs.len())?;
    let scope_set = normalized_scope.as_ref().map(|indices| {
        indices
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
    });

    let mut analysis_psbt = psbt.clone();
    let mut scoped_known_inscriptions: HashMap<(Txid, u32), Vec<(String, u64)>> = HashMap::new();
    let mut scope_has_unknown_inputs = false;

    if let Some(scope_indices) = normalized_scope.as_ref() {
        for &index in scope_indices {
            let _ = input_value_for_audit(psbt, index, true)?;
            let outpoint = psbt.unsigned_tx.input[index].previous_output;
            if let Some(items) = known_inscriptions.get(&(outpoint.txid, outpoint.vout)) {
                scoped_known_inscriptions.insert((outpoint.txid, outpoint.vout), items.clone());
            }
        }

        for index in 0..analysis_psbt.inputs.len() {
            if scope_indices.binary_search(&index).is_ok() {
                continue;
            }
            if input_value_for_audit(psbt, index, false)?.is_none() {
                analysis_psbt.inputs[index].witness_utxo = Some(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(0),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                });
                scope_has_unknown_inputs = true;
            }
        }
    }

    let mut warning_level = WarningLevel::Safe;
    let mut inscriptions_burned = Vec::new();
    let mut inscription_destinations = HashMap::new();
    let mut fee_sats = 0;
    let mut warnings = Vec::new();

    let mut inputs_info = Vec::new();
    let mut outputs_info = Vec::new();

    // Check SIGHASH safety
    // Only checking ECDSA sighash for now as we key off psbt.inputs[i].sighash_type
    for (i, input) in analysis_psbt.inputs.iter().enumerate() {
        if scope_set
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&i))
        {
            continue;
        }

        if let Some(sighash) = input.sighash_type {
            // PsbtSighashType wraps u32. Check raw values for safety.
            let val = sighash.to_u32();
            let base_type = val & 0x1f; // Bottom 5 bits
            let anyone_can_pay = (val & 0x80) != 0;

            if anyone_can_pay {
                warning_level = WarningLevel::Warn;
                warnings.push(format!(
                    "Input #{} uses ANYONECANPAY. Inputs can be added.",
                    i
                ));
            }

            match base_type {
                2 => {
                    // SIGHASH_NONE
                    warning_level = WarningLevel::Danger;
                    warnings.push(format!(
                        "Input #{} uses SIGHASH_NONE. Outputs can be changed!",
                        i
                    ));
                }
                3 => {
                    // SIGHASH_SINGLE
                    // Single is dangerous if not coupled with output check
                    if warning_level != WarningLevel::Danger {
                        warning_level = WarningLevel::Warn;
                    }
                    warnings.push(format!(
                        "Input #{} uses SIGHASH_SINGLE. Check output matching.",
                        i
                    ));
                }
                _ => {} // ALL (1) or others
            }
        }
    }

    // 1. Calculate Input Ranges & Total Input Value
    let mut total_input_value = 0u64;
    let mut accumulated_input_offset = 0u64;

    // Store absolute offsets of all inscriptions being moved
    // (InscriptionID/Key, AbsoluteOffset, OriginalInputValue)
    let mut active_inscriptions: Vec<(String, u64, u64)> = Vec::new();

    zinc_log_debug!(target: LOG_TARGET_SHIELD, "analyze_psbt core: Processing {} inputs", analysis_psbt.inputs.len());

    for (i, input) in analysis_psbt.inputs.iter().enumerate() {
        if scope_set
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&i))
        {
            continue;
        }

        let utxo = &input.witness_utxo;

        // Log input details for debugging
        if let Some(wu) = utxo {
            zinc_log_debug!(target: LOG_TARGET_SHIELD,
                "Input #{} HAS witness_utxo. Value: {}, SPK: {}",
                i,
                wu.value.to_sat(),
                wu.script_pubkey.to_hex_string()
            );
        } else {
            zinc_log_debug!(target: LOG_TARGET_SHIELD, "Input #{} MISSING witness_utxo", i);
        }

        // "Blind Spot" Check
        let value = if let Some(txout) = &utxo {
            txout.value.to_sat()
        } else if let Some(prev_tx) = &analysis_psbt.inputs[i].non_witness_utxo {
            // Fallback: Try to find value in non_witness_utxo (Legacy/SegWit v0 full tx)
            let vout_idx = analysis_psbt.unsigned_tx.input[i].previous_output.vout as usize;
            if let Some(output) = prev_tx.output.get(vout_idx) {
                zinc_log_debug!(target: LOG_TARGET_SHIELD,
                    "Input #{} recovered via non_witness_utxo. Value: {}",
                    i,
                    output.value.to_sat()
                );
                output.value.to_sat()
            } else {
                zinc_log_debug!(target: LOG_TARGET_SHIELD,
                    "analyze_psbt: Input #{} non_witness_utxo mismatch (vout out of bounds)",
                    i
                );
                return Err(OrdError::RequestFailed(format!(
                    "Ordinal Shield Error: Input #{} non_witness_utxo found but vout index {} invalid.",
                    i, vout_idx
                )));
            }
        } else {
            zinc_log_debug!(target: LOG_TARGET_SHIELD, "analyze_psbt: BLIND SPOT at input #{} - returning error", i);
            return Err(OrdError::RequestFailed(format!(
                "Ordinal Shield Error: Input #{} missing witness_utxo data. Cannot safely analyze.",
                i
            )));
        };

        let outpoint = analysis_psbt.unsigned_tx.input[i].previous_output;

        // Check if this input has known inscriptions
        let mut input_inscriptions_ids = Vec::new();
        let known_map = if normalized_scope.is_some() {
            &scoped_known_inscriptions
        } else {
            known_inscriptions
        };

        if let Some(items) = known_map.get(&(outpoint.txid, outpoint.vout)) {
            zinc_log_debug!(target: LOG_TARGET_SHIELD,
                "Input #{} MATCHES! Found {} inscriptions at outpoint {}",
                i,
                items.len(),
                outpoint
            );
            for (id, relative_offset) in items {
                let absolute_offset = accumulated_input_offset + relative_offset;
                active_inscriptions.push((id.clone(), absolute_offset, value));
                input_inscriptions_ids.push(id.clone());
            }
        } else {
            zinc_log_debug!(target: LOG_TARGET_SHIELD, "Input #{} NO MATCH (outpoint: {})", i, outpoint);
        }

        let address = utxo.as_ref().and_then(|u| {
            bitcoin::Address::from_script(&u.script_pubkey, network)
                .ok()
                .map(|a| a.to_string())
        });

        inputs_info.push(InputInfo {
            txid: outpoint.txid.to_string(),
            vout: outpoint.vout,
            value,
            script_pubkey: utxo
                .as_ref()
                .map(|u| u.script_pubkey.to_hex_string())
                .unwrap_or_default(),
            address,
            is_mine: false, // Don't know without wallet context
            inscriptions: input_inscriptions_ids,
        });

        total_input_value += value;
        accumulated_input_offset += value;
    }

    // 2. Map to Outputs
    let mut current_output_offset = 0u64;
    for (vout, output) in analysis_psbt.unsigned_tx.output.iter().enumerate() {
        let output_value = output.value.to_sat();
        let output_end = current_output_offset + output_value;

        let address = bitcoin::Address::from_script(&output.script_pubkey, network)
            .ok()
            .map(|a| a.to_string());

        let mut output_inscriptions = Vec::new();

        // Check which inscriptions fall into this output's range
        for (key, abs_offset, original_input_value) in &active_inscriptions {
            if *abs_offset >= current_output_offset && *abs_offset < output_end {
                // Found destination!
                let relative_offset = abs_offset - current_output_offset;

                let Ok(safe_vout) = u32::try_from(vout) else {
                    return Err(OrdError::RequestFailed(format!(
                        "Ordinal Shield Error: Output index {} is too large.",
                        vout
                    )));
                };

                inscription_destinations.insert(
                    key.clone(),
                    InscriptionDestination {
                        vout: Some(safe_vout),
                        offset: relative_offset,
                    },
                );
                output_inscriptions.push(key.clone());

                // Burial Check: Merging into large UTXO (> 10k sats)
                // Only warn if not already Danger
                if output_value > 10_000 && warning_level == WarningLevel::Safe {
                    warning_level = WarningLevel::Warn;
                }

                // Warn if UTXO size changed (Output Value != Input Value)
                if output_value != *original_input_value {
                    warning_level = WarningLevel::Warn;
                    warnings.push(format!(
                        "Inscription {} UTXO size changed ({} -> {} sats). Verify this is intended.", 
                        shorten_id(key), original_input_value, output_value
                    ));
                }
            }
        }

        outputs_info.push(OutputInfo {
            vout: vout as u32,
            value: output_value,
            script_pubkey: output.script_pubkey.to_hex_string(),
            address,
            is_change: false, // Don't know
            inscriptions: output_inscriptions,
        });

        current_output_offset += output_value;
    }

    // 3. Check for Burns (Fees)
    let total_output_value = current_output_offset;
    if total_input_value >= total_output_value {
        fee_sats = total_input_value - total_output_value;
    }

    for (key, _, _) in &active_inscriptions {
        if !inscription_destinations.contains_key(key) {
            // It wasn't found in any output range -> BURNED
            inscriptions_burned.push(key.clone());
            warning_level = WarningLevel::Danger;

            // Record it as burned in destinations too for completeness
            inscription_destinations.insert(
                key.clone(),
                InscriptionDestination {
                    vout: None,
                    offset: 0,
                },
            );
        }
    }

    zinc_log_debug!(target: LOG_TARGET_SHIELD,
        "analyze_psbt core finished: Safe? {:?}, Fee: {} sats, Mapped: {}",
        warning_level,
        fee_sats,
        inscription_destinations.len()
    );

    if let Some(scope_indices) = normalized_scope {
        warnings.push(format!(
            "Partial-scope audit: analyzed only requested inputs [{}]. Unscoped inputs may alter final inscription movement.",
            scope_indices
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));

        if scope_has_unknown_inputs {
            warnings.push(
                "Some unscoped inputs had missing UTXO metadata; sat-flow precision is reduced."
                    .to_string(),
            );
        }

        if warning_level == WarningLevel::Safe {
            warning_level = WarningLevel::Warn;
        }
    }

    Ok(AnalysisResult {
        warning_level,
        inscriptions_burned,
        inscription_destinations,

        fee_sats,
        warnings,
        inputs: inputs_info,
        outputs: outputs_info,
    })
}

fn shorten_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}...", &id[0..8])
    } else {
        id.to_string()
    }
}

/// Audits a PSBT under the current warn-only Ordinal Shield policy.
///
/// This function validates that the PSBT can be analyzed and computes risk signals
/// (burn risk, destination issues, sighash concerns), but does not hard-reject based
/// on warning level. UI surfaces these warnings and the user decides whether to sign.
///
/// Returns `Ok(())` when analysis succeeds, `Err(OrdError)` only when parsing/analysis fails.
pub fn audit_psbt(
    psbt: &Psbt,
    known_inscriptions: &HashMap<(Txid, u32), Vec<(String, u64)>>,
    input_scope: Option<&[usize]>,
    network: bitcoin::Network,
) -> Result<(), OrdError> {
    // Pre-popup gate: validates the PSBT can be parsed and analyzed.
    // All risk signals (burns, size mismatches, non-taproot, sighash)
    // are shown as warnings in the popup — the user decides.
    let _analysis = analyze_psbt_with_scope(psbt, known_inscriptions, input_scope, network)?;
    Ok(())
}
