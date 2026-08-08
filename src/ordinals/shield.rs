use crate::ordinals::error::OrdError;
use crate::ordinals::runes::{simulate_rune_flow, RuneActions, RuneAmount};
use bitcoin::{OutPoint, Psbt, Txid};
use ordinals::{Artifact, RuneId, Runestone};
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
/// Inscription detected inside an unsigned tapscript (i.e. currently being minted).
pub struct NewInscription {
    /// The MIME type of the inscription.
    pub content_type: String,
    /// Base64 encoded payload body.
    pub body_base64: String,
    /// Index of the PSBT input that contains the inscription tapscript.
    pub input_index: usize,
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
    /// Rune amounts known to sit on this input's outpoint (wallet cache).
    #[serde(default)]
    pub runes: Vec<RuneAmount>,
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
    /// Simulated rune amounts this output would receive.
    #[serde(default)]
    pub runes: Vec<RuneAmount>,
    /// True when the script is `OP_RETURN` (runes allocated here are burned).
    #[serde(default)]
    pub is_op_return: bool,
    /// True when the value is below the script's minimal non-dust threshold.
    /// Always `false` for `OP_RETURN` outputs.
    #[serde(default)]
    pub is_dust: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Full Ordinal Shield analysis report for a candidate PSBT.
pub struct AnalysisResult {
    /// Overall risk level.
    pub warning_level: WarningLevel,
    #[serde(default)]
    /// Inscriptions that are currently being minted in this transaction.
    pub new_inscriptions: Vec<NewInscription>,
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
    /// Runestone/cenotaph summary. `None` when the transaction has no
    /// runestone and no analyzed input holds runes (or when rune context was
    /// not provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rune_actions: Option<RuneActions>,
    /// Estimated fee rate in sat/vB. `None` when a witness size cannot be
    /// estimated for some input. For unsigned PSBTs this assumes single-key
    /// spends (taproot key-path, P2WPKH); script-path and multisig spends
    /// will be underestimated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_rate_sat_vb: Option<f64>,
    /// Whether the sat-flow simulation had complete prevout values for EVERY
    /// input and therefore produced trustworthy absolute ordinal offsets.
    ///
    /// Ordinal offsets are absolute across the whole input list, so a single
    /// input of unknown value invalidates every inscription destination and
    /// the fee. When this is `false`, `inscription_destinations`,
    /// `inscriptions_burned` and `fee_sats` are suppressed rather than
    /// reported wrong — treat the transaction as unanalyzed, not as safe.
    ///
    /// Defaults to `false` on deserialize so an older payload that predates
    /// this field is read as untrustworthy rather than trusted.
    #[serde(default)]
    pub sat_flow_reliable: bool,
    /// Whether the inscription set this analysis was measured against came
    /// from a completed, successful ordinals resolve.
    ///
    /// When `false` the wallet's inscription cache is empty, stale, or was
    /// never confirmed by the indexer, so `inscriptions_burned: []` means
    /// "nothing known" rather than "nothing at risk". Every transaction-
    /// BUILDING path already refuses to run in this state ("safety lock
    /// engaged"); the dapp-facing analyze path cannot refuse, so it reports
    /// the condition instead. Approval UIs should badge or block on it.
    ///
    /// Defaults to `false` on deserialize: an unverified reading is the safe
    /// interpretation of a payload that predates this field.
    #[serde(default)]
    pub assets_verified: bool,
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

/// Per-outpoint rune holdings, keyed like `known_inscriptions`. Values are
/// `("block:tx" rune id, raw amount in base units)`.
pub type KnownRunes = HashMap<(Txid, u32), Vec<(String, u128)>>;

/// Wallet-cached knowledge bundled for offline PSBT analysis.
pub struct ShieldContext<'a> {
    /// Inscriptions known per spent outpoint.
    pub known_inscriptions: &'a HashMap<(Txid, u32), Vec<(String, u64)>>,
    /// Rune holdings known per spent outpoint.
    pub known_runes: &'a KnownRunes,
    /// Optional input scope for partial-signing flows.
    pub input_scope: Option<&'a [usize]>,
    /// Network used for address rendering.
    pub network: bitcoin::Network,
    /// Cached per-mint amounts keyed by rune id `"block:tx"`, used to resolve
    /// mint amounts offline when the terms are known.
    pub mint_terms: &'a HashMap<String, u128>,
    /// Whether `known_inscriptions` / `known_runes` came from a completed,
    /// successful ordinals resolve (the wallet's `ordinals_verified` state).
    ///
    /// Pass `false` whenever the caches are empty, stale, or unconfirmed. An
    /// empty cache is otherwise indistinguishable from a verified-clean
    /// transaction, which is exactly what a hostile or lagging ord indexer
    /// would exploit.
    pub assets_verified: bool,
}

/// Analyze a PSBT with full wallet context: inscription sat flow plus rune
/// flow simulation, fee-rate estimation, and dust flags.
///
/// This wraps [`analyze_psbt_with_scope`] and post-processes its result; the
/// legacy entry points remain available and rune-blind.
pub fn analyze_psbt_with_context(
    psbt: &Psbt,
    ctx: &ShieldContext<'_>,
) -> Result<AnalysisResult, OrdError> {
    let mut analysis =
        analyze_psbt_with_scope(psbt, ctx.known_inscriptions, ctx.input_scope, ctx.network)?;
    apply_asset_verification(&mut analysis, ctx.assets_verified);
    let tx = &psbt.unsigned_tx;

    // A suppressed fee is not a zero fee; do not derive a rate from it.
    analysis.fee_rate_sat_vb = if analysis.sat_flow_reliable {
        estimate_fee_rate_sat_vb(psbt, analysis.fee_sats)
    } else {
        None
    };

    // Per-input rune holdings from the wallet cache.
    let mut input_holdings: Vec<Vec<(RuneId, u128)>> = Vec::with_capacity(tx.input.len());
    let mut any_input_runes = false;
    for (index, input) in tx.input.iter().enumerate() {
        let key = (input.previous_output.txid, input.previous_output.vout);
        let mut holdings: Vec<(RuneId, u128)> = Vec::new();
        if let Some(entries) = ctx.known_runes.get(&key) {
            for (id, amount) in entries {
                if let Ok(rune_id) = id.parse::<RuneId>() {
                    holdings.push((rune_id, *amount));
                }
            }
        }
        if !holdings.is_empty() {
            any_input_runes = true;
            if let Some(info) = analysis.inputs.get_mut(index) {
                info.runes = holdings
                    .iter()
                    .map(|(id, amount)| RuneAmount::new(id.to_string(), *amount))
                    .collect();
            }
        }
        input_holdings.push(holdings);
    }

    let artifact = Runestone::decipher(tx);
    if artifact.is_none() && !any_input_runes {
        return Ok(analysis);
    }

    // Partial scope cannot see unscoped inputs' runes: never emit exact
    // amounts that might be wrong.
    if ctx.input_scope.is_some() {
        analysis.warnings.push(
            "Rune flow is not simulated under partial-scope analysis; rune movement may be incomplete.".to_string(),
        );
        if analysis.warning_level == WarningLevel::Safe {
            analysis.warning_level = WarningLevel::Warn;
        }
        return Ok(analysis);
    }

    let mint_amount = artifact
        .as_ref()
        .and_then(Artifact::mint)
        .and_then(|id| ctx.mint_terms.get(&id.to_string()).copied());

    let flow = simulate_rune_flow(tx, &input_holdings, mint_amount);

    for (vout, entries) in flow.output_runes.iter().enumerate() {
        if entries.is_empty() {
            continue;
        }
        if let Some(info) = analysis.outputs.get_mut(vout) {
            info.runes = entries
                .iter()
                .map(|(id, amount)| RuneAmount::new(id.clone(), *amount))
                .collect();
        }
    }

    analysis.warnings.extend(flow.warnings);
    let escalate_to_warn = flow.actions.etching.is_some()
        || flow.actions.mint_amount_unknown
        || flow.actions.default_transfer_without_runestone;
    if flow.danger {
        analysis.warning_level = WarningLevel::Danger;
    } else if escalate_to_warn && analysis.warning_level == WarningLevel::Safe {
        analysis.warning_level = WarningLevel::Warn;
    }
    analysis.rune_actions = Some(flow.actions);

    Ok(analysis)
}

/// Records whether the inscription/rune caches behind an analysis were
/// actually verified, and downgrades the verdict when they were not.
///
/// The shield's clean verdict is only as good as the asset data it was
/// measured against. With an empty or stale cache the sat-flow simulation
/// finds nothing to move and reports `warning_level: Safe` with
/// `inscriptions_burned: []` — indistinguishable from a genuinely clean
/// transaction. Every transaction-building path in this crate refuses to run
/// unverified; the dapp-facing analyze path cannot refuse, so it must say so.
pub fn apply_asset_verification(analysis: &mut AnalysisResult, assets_verified: bool) {
    analysis.assets_verified = assets_verified;
    if assets_verified {
        return;
    }

    analysis.warnings.push(
        "Inscription and rune data for this wallet is unverified. A clean result here does not mean this transaction is safe."
            .to_string(),
    );
    if analysis.warning_level == WarningLevel::Safe {
        analysis.warning_level = WarningLevel::Warn;
    }
}

/// Estimates the fee rate in sat/vB for a possibly-unsigned PSBT.
///
/// Uses actual final witnesses when present; otherwise estimates witness
/// weight per input script type (taproot key-path ≈ 66 WU, P2WPKH ≈ 108 WU,
/// legacy P2PKH scriptsig ≈ 107 bytes). Returns `None` for input types whose
/// spend size cannot be estimated (P2WSH, bare/unknown scripts) rather than
/// reporting a wrong number.
fn estimate_fee_rate_sat_vb(psbt: &Psbt, fee_sats: u64) -> Option<f64> {
    let tx = &psbt.unsigned_tx;
    if fee_sats == 0 {
        return Some(0.0);
    }
    let base_weight = tx.weight().to_wu();
    let mut witness_weight: u64 = 0;
    let mut any_witness = false;

    for (index, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness) = input.final_script_witness.as_ref() {
            witness_weight += witness.size() as u64;
            any_witness = true;
            continue;
        }
        let script_pubkey = input
            .witness_utxo
            .as_ref()
            .map(|utxo| utxo.script_pubkey.clone())
            .or_else(|| {
                input.non_witness_utxo.as_ref().and_then(|prev| {
                    prev.output
                        .get(tx.input[index].previous_output.vout as usize)
                        .map(|output| output.script_pubkey.clone())
                })
            })?;

        if script_pubkey.is_p2tr() {
            // count(1) + len(1) + schnorr sig(64)
            witness_weight += 66;
            any_witness = true;
        } else if script_pubkey.is_p2wpkh() {
            // count(1) + sig(1+72) + pubkey(1+33)
            witness_weight += 108;
            any_witness = true;
        } else if script_pubkey.is_p2pkh() {
            // scriptsig sig(1+72) + pubkey(1+33) + push overhead; base data
            // counts 4 WU per byte.
            witness_weight += 107 * 4;
        } else {
            return None;
        }
    }

    let marker_flag_weight = if any_witness { 2 } else { 0 };
    let total_weight = base_weight + witness_weight + marker_flag_weight;
    let vsize = total_weight.div_ceil(4);
    if vsize == 0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    Some(fee_sats as f64 / vsize as f64)
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
            "Ordinal Shield Error: input scope index {index} is out of bounds ({input_count} inputs)."
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
                    "Ordinal Shield Error: Input #{index} non_witness_utxo found but vout index {vout_idx} invalid."
                ))
            });
    }

    if require_metadata {
        return Err(OrdError::RequestFailed(format!(
            "Ordinal Shield Error: Input #{index} missing witness_utxo data. Cannot safely analyze."
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

    let analysis_psbt = psbt.clone();
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

        // Unscoped inputs still need prevout values: ordinal offsets are
        // absolute across the whole input list. Note which ones we cannot
        // value instead of fabricating a zero-value txout for them — the main
        // loop below records the same fact and the result is suppressed.
        for index in 0..analysis_psbt.inputs.len() {
            if scope_indices.binary_search(&index).is_ok() {
                continue;
            }
            if input_value_for_audit(psbt, index, false)?.is_none() {
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
    let mut new_inscriptions = Vec::new();

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
                    "Input #{i} uses ANYONECANPAY. Inputs can be added."
                ));
            }

            match base_type {
                2 => {
                    // SIGHASH_NONE
                    warning_level = WarningLevel::Danger;
                    warnings.push(format!(
                        "Input #{i} uses SIGHASH_NONE. Outputs can be changed!"
                    ));
                }
                3 => {
                    // SIGHASH_SINGLE
                    // Single is dangerous if not coupled with output check
                    if warning_level != WarningLevel::Danger {
                        warning_level = WarningLevel::Warn;
                    }
                    warnings.push(format!(
                        "Input #{i} uses SIGHASH_SINGLE. Check output matching."
                    ));
                }
                _ => {} // ALL (1) or others
            }
        }
    }

    // 1. Calculate Input Ranges & Total Input Value
    //
    // SECURITY: ordinal sat offsets are ABSOLUTE across the entire input list.
    // Every input advances the running offset and the input total, including
    // inputs outside the signing scope. Skipping unscoped inputs here (as this
    // loop used to) understates each inscription's absolute offset, so the
    // output-mapping loop below resolves it to an earlier output than reality,
    // and undercounts total_input_value so the fee collapses toward 0. Under
    // the ordinary dapp pattern signPsbt(psbt, { signInputs: [1] }) that let
    // the shield report a concrete safe-looking destination for an inscription
    // that is really burned to fee.
    let mut total_input_value = 0u64;
    let mut accumulated_input_offset = 0u64;

    // Store absolute offsets of all inscriptions being moved
    // (InscriptionID/Key, AbsoluteOffset, OriginalInputValue)
    let mut active_inscriptions: Vec<(String, u64, u64)> = Vec::new();

    zinc_log_debug!(target: LOG_TARGET_SHIELD, "analyze_psbt core: Processing {} inputs", analysis_psbt.inputs.len());

    for (i, input) in analysis_psbt.inputs.iter().enumerate() {
        let in_scope = scope_set
            .as_ref()
            .map_or(true, |allowed| allowed.contains(&i));

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
                    "Ordinal Shield Error: Input #{i} non_witness_utxo found but vout index {vout_idx} invalid."
                )));
            }
        } else if in_scope {
            zinc_log_debug!(target: LOG_TARGET_SHIELD, "analyze_psbt: BLIND SPOT at input #{} - returning error", i);
            return Err(OrdError::RequestFailed(format!(
                "Ordinal Shield Error: Input #{i} missing witness_utxo data. Cannot safely analyze."
            )));
        } else {
            // An unscoped input we cannot value. It still occupies sat range in
            // the ordinal ordering, so every offset after it is now guesswork.
            zinc_log_debug!(target: LOG_TARGET_SHIELD, "analyze_psbt: unscoped input #{} has unknown value - sat flow unreliable", i);
            scope_has_unknown_inputs = true;
            0
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
            runes: Vec::new(), // Filled by analyze_psbt_with_context
        });

        // Look for Ordinal envelopes in the witness/tap_scripts
        for (script, _) in input.tap_scripts.values() {
            let script_bytes = script.as_bytes();
            let envelope_marker = [0x00, 0x63, 0x03, 0x6f, 0x72, 0x64];
            let mut search_pos = 0;

            while let Some(pos) = script_bytes[search_pos..]
                .windows(envelope_marker.len())
                .position(|window| window == envelope_marker)
            {
                let absolute_pos = search_pos + pos;
                let mut cursor = absolute_pos + envelope_marker.len();
                let mut content_type = "Unknown".to_string();
                let mut body = Vec::new();
                let mut is_valid = false;

                // Parse Tags until OP_0 (Separator) or OP_ENDIF
                while cursor < script_bytes.len() {
                    let opcode = script_bytes[cursor];
                    if opcode == 0x00 {
                        cursor += 1;
                        is_valid = true;
                        break;
                    }
                    if opcode == 0x68 {
                        cursor += 1;
                        break;
                    }

                    if opcode == 0x01 {
                        // Tag Push (OP_PUSHBYTES_1)
                        if cursor + 1 >= script_bytes.len() {
                            break;
                        }
                        let tag = script_bytes[cursor + 1];
                        cursor += 2;

                        if cursor >= script_bytes.len() {
                            break;
                        }
                        let val_opcode = script_bytes[cursor];
                        let (val_len, header_len) = if val_opcode <= 75 {
                            (val_opcode as usize, 1)
                        } else if val_opcode == 0x4c {
                            if cursor + 2 <= script_bytes.len() {
                                (script_bytes[cursor + 1] as usize, 2)
                            } else {
                                (0, 0)
                            }
                        } else if val_opcode == 0x4d {
                            if cursor + 3 <= script_bytes.len() {
                                (
                                    u16::from_le_bytes(
                                        script_bytes[cursor + 1..cursor + 3].try_into().unwrap(),
                                    ) as usize,
                                    3,
                                )
                            } else {
                                (0, 0)
                            }
                        } else {
                            (0, 0)
                        };

                        if header_len > 0 && cursor + header_len + val_len <= script_bytes.len() {
                            let val_bytes =
                                &script_bytes[cursor + header_len..cursor + header_len + val_len];
                            if tag == 1 {
                                if let Ok(ct) = String::from_utf8(val_bytes.to_vec()) {
                                    content_type = ct;
                                }
                            }
                            cursor += header_len + val_len;
                        } else {
                            break;
                        }
                    } else {
                        // Skip unknown tags
                        if cursor >= script_bytes.len() {
                            break;
                        }
                        let op = script_bytes[cursor];
                        let (skip_len, header_len) = if op <= 75 {
                            (op as usize, 1)
                        } else if op == 0x4c {
                            if cursor + 2 <= script_bytes.len() {
                                (script_bytes[cursor + 1] as usize, 2)
                            } else {
                                (0, 0)
                            }
                        } else if op == 0x4d {
                            if cursor + 3 <= script_bytes.len() {
                                (
                                    u16::from_le_bytes(
                                        script_bytes[cursor + 1..cursor + 3].try_into().unwrap(),
                                    ) as usize,
                                    3,
                                )
                            } else {
                                (0, 0)
                            }
                        } else {
                            (0, 0)
                        };
                        cursor += header_len + skip_len;
                    }
                }

                if is_valid {
                    // Extract body
                    while cursor < script_bytes.len() {
                        let opcode = script_bytes[cursor];
                        if opcode == 0x68 {
                            // OP_ENDIF
                            break;
                        }

                        let (val_len, header_len) = if opcode <= 75 {
                            (opcode as usize, 1)
                        } else if opcode == 0x4c {
                            if cursor + 2 <= script_bytes.len() {
                                (script_bytes[cursor + 1] as usize, 2)
                            } else {
                                (0, 0)
                            }
                        } else if opcode == 0x4d {
                            if cursor + 3 <= script_bytes.len() {
                                (
                                    u16::from_le_bytes(
                                        script_bytes[cursor + 1..cursor + 3].try_into().unwrap(),
                                    ) as usize,
                                    3,
                                )
                            } else {
                                (0, 0)
                            }
                        } else {
                            (0, 0)
                        };

                        if header_len > 0 && cursor + header_len + val_len <= script_bytes.len() {
                            body.extend_from_slice(
                                &script_bytes[cursor + header_len..cursor + header_len + val_len],
                            );
                            cursor += header_len + val_len;
                        } else {
                            break;
                        }
                    }

                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                    new_inscriptions.push(NewInscription {
                        content_type,
                        body_base64: STANDARD.encode(&body),
                        input_index: i,
                    });
                }

                search_pos = absolute_pos + envelope_marker.len();
            }
        }

        total_input_value += value;
        accumulated_input_offset += value;
    }

    // 2. Map to Outputs
    let mut current_output_offset = 0u64;
    for (vout, output) in analysis_psbt.unsigned_tx.output.iter().enumerate() {
        // SECURITY: convert the output index once, up front, instead of an unchecked
        // `as u32` truncation; fail loudly rather than silently corrupting the index.
        let vout_u32 = u32::try_from(vout).map_err(|_| {
            OrdError::RequestFailed(format!(
                "Ordinal Shield Error: Output index {vout} exceeds u32 limit"
            ))
        })?;

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

                inscription_destinations.insert(
                    key.clone(),
                    InscriptionDestination {
                        vout: Some(vout_u32),
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

        let is_op_return = output.script_pubkey.is_op_return();
        outputs_info.push(OutputInfo {
            vout: vout_u32,
            value: output_value,
            script_pubkey: output.script_pubkey.to_hex_string(),
            address,
            is_change: false, // Don't know
            inscriptions: output_inscriptions,
            runes: Vec::new(), // Filled by analyze_psbt_with_context
            is_op_return,
            is_dust: !is_op_return
                && output_value < output.script_pubkey.minimal_non_dust().to_sat(),
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

        if warning_level == WarningLevel::Safe {
            warning_level = WarningLevel::Warn;
        }
    }

    // An input we could not value breaks the absolute sat ordering for every
    // inscription after it and makes the fee meaningless. Publish nothing
    // computed from it: a wrong destination reads as reassurance, and the
    // burn-to-fee case is exactly where that reassurance is fatal.
    let sat_flow_reliable = !scope_has_unknown_inputs;
    if scope_has_unknown_inputs {
        warnings.push(
            "Some inputs have unknown value. Ordinal sat offsets are absolute across all inputs, so inscription destinations and the fee cannot be computed for this transaction."
                .to_string(),
        );

        if active_inscriptions.is_empty() {
            if warning_level == WarningLevel::Safe {
                warning_level = WarningLevel::Warn;
            }
        } else {
            warning_level = WarningLevel::Danger;
            warnings.push(
                "This transaction moves inscriptions but their destinations could not be verified. Do not assume they are safe."
                    .to_string(),
            );
        }

        inscription_destinations.clear();
        inscriptions_burned.clear();
        fee_sats = 0;
        for output in &mut outputs_info {
            output.inscriptions.clear();
        }
    }

    Ok(AnalysisResult {
        warning_level,
        new_inscriptions,
        inscriptions_burned,
        inscription_destinations,

        fee_sats,
        warnings,
        inputs: inputs_info,
        outputs: outputs_info,
        rune_actions: None,    // Filled by analyze_psbt_with_context
        fee_rate_sat_vb: None, // Filled by analyze_psbt_with_context
        sat_flow_reliable,
        // This entry point has no wallet context and therefore no way to know
        // whether the inscription set it was handed is verified. Callers that
        // do know must say so via apply_asset_verification (or ShieldContext).
        assets_verified: false,
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
