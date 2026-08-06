//! Vendor-neutral capability negotiation for external signers.
//!
//! Zinc derives [`ExternalSigningRequirementsV2`] from the exact PSBT that will
//! be handed to a signer. A hardware-wallet adapter independently describes the
//! effective capabilities of its provider/model/firmware/transport combination
//! with [`ExternalSignerCapabilitiesV2`]. The matcher in this module is pure and
//! deny-by-default: every derived requirement must be explicitly supported.

use bitcoin::psbt::Psbt;
use bitcoin::script::{Instruction, Script};
use bitcoin::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Schema version for per-input external-signing capability negotiation.
pub const EXTERNAL_SIGNING_SCHEMA_V2: u16 = 2;

/// Script/signing mechanism required for an input Zinc asks the device to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSigningInputTypeV1 {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2trKeyPath,
    P2trScriptPath,
    ArbitraryScript,
}

impl ExternalSigningInputTypeV1 {
    const fn capability_key(self) -> &'static str {
        match self {
            Self::P2pkh => "input.p2pkh",
            Self::P2sh => "input.p2sh",
            Self::P2wpkh => "input.p2wpkh",
            Self::P2wsh => "input.p2wsh",
            Self::P2trKeyPath => "input.p2tr_key_path",
            Self::P2trScriptPath => "input.p2tr_script_path",
            Self::ArbitraryScript => "input.arbitrary_script",
        }
    }
}

/// Exact output representation a signer must be able to review and serialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSigningOutputTypeV1 {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    /// `OP_RETURN` followed by exactly one pushed byte string.
    OpReturnPushData,
    /// A Runes protocol output beginning with `OP_RETURN OP_13`.
    Runestone,
    /// Any output not covered by a more precise variant.
    ArbitraryScript,
}

impl ExternalSigningOutputTypeV1 {
    const fn capability_key(self) -> &'static str {
        match self {
            Self::P2pkh => "output.p2pkh",
            Self::P2sh => "output.p2sh",
            Self::P2wpkh => "output.p2wpkh",
            Self::P2wsh => "output.p2wsh",
            Self::P2tr => "output.p2tr",
            Self::OpReturnPushData => "output.op_return_push_data",
            Self::Runestone => "output.runestone",
            Self::ArbitraryScript => "output.arbitrary_script",
        }
    }
}

/// Optional signer limits which can vary by model, firmware, or transport.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerLimitsV1 {
    pub max_inputs: Option<usize>,
    pub max_outputs: Option<usize>,
}

/// Exact signing requirement for one input. Keeping the input type and
/// sighash together prevents a signer from appearing compatible merely because
/// it supports each value independently on different script families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningInputRequirementV2 {
    pub index: usize,
    pub input_type: ExternalSigningInputTypeV1,
    pub sighash_type: u32,
}

/// Requirements derived from the exact prepared PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningRequirementsV2 {
    pub schema_version: u16,
    pub required_inputs: Vec<ExternalSigningInputRequirementV2>,
    pub output_types: BTreeSet<ExternalSigningOutputTypeV1>,
    pub input_count: usize,
    pub output_count: usize,
    pub has_external_inputs: bool,
    pub requires_selective_signing: bool,
}

/// Sighash policy for one signer-supported input family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerInputPolicyV2 {
    pub input_type: ExternalSigningInputTypeV1,
    pub supported_sighash_types: BTreeSet<u32>,
    pub default_sighash_type: u32,
}

/// Effective capabilities supplied by a hardware-wallet adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerCapabilitiesV2 {
    pub schema_version: u16,
    pub signer: String,
    pub input_signing_policies: Vec<ExternalSignerInputPolicyV2>,
    pub supported_output_types: BTreeSet<ExternalSigningOutputTypeV1>,
    pub supports_external_inputs: bool,
    pub supports_selective_signing: bool,
    #[serde(default)]
    pub limits: ExternalSignerLimitsV1,
}

impl ExternalSignerCapabilitiesV2 {
    /// Start with an empty, deny-by-default capability set.
    #[must_use]
    pub fn deny_all(signer: impl Into<String>) -> Self {
        Self {
            schema_version: EXTERNAL_SIGNING_SCHEMA_V2,
            signer: signer.into(),
            input_signing_policies: Vec::new(),
            supported_output_types: BTreeSet::new(),
            supports_external_inputs: false,
            supports_selective_signing: false,
            limits: ExternalSignerLimitsV1::default(),
        }
    }
}

/// Stable V2 rejection categories suitable for RPC/UI handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRejectionCodeV2 {
    SchemaVersionUnsupported,
    CapabilityUnsupported,
    SighashUnsupportedForInput,
    TransactionNotRepresentable,
    DeviceLimitExceeded,
}

/// A typed V2 reason an external signer must not receive a PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRejectionV2 {
    pub code: CapabilityRejectionCodeV2,
    pub capability: String,
    pub message: String,
    pub input_index: Option<usize>,
    pub input_type: Option<ExternalSigningInputTypeV1>,
    pub required_sighash_type: Option<u32>,
    pub supported_sighash_types: Option<BTreeSet<u32>>,
}

impl fmt::Display for CapabilityRejectionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.capability, self.message)
    }
}

impl std::error::Error for CapabilityRejectionV2 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerCompatibilityV2 {
    pub compatible: bool,
    pub rejections: Vec<CapabilityRejectionV2>,
}

/// Typed failures encountered while deriving requirements from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequirementsDerivationError {
    #[error("required input index {input_index} is out of bounds for {input_count} inputs")]
    RequiredInputOutOfBounds {
        input_index: usize,
        input_count: usize,
    },
    #[error("required input index {input_index} is duplicated")]
    DuplicateRequiredInput { input_index: usize },
    #[error("input #{input_index} is missing prevout metadata")]
    MissingPrevout { input_index: usize },
    #[error("input #{input_index} references missing previous output #{vout}")]
    MissingPreviousOutput { input_index: usize, vout: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningDerivationV1 {
    pub master_fingerprint_hex: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningPlanInputV2 {
    pub index: usize,
    pub prev_hash: String,
    pub prev_index: u32,
    pub amount_sats: String,
    pub sequence: u32,
    pub script_pubkey_hex: String,
    pub input_type: ExternalSigningInputTypeV1,
    pub sighash_type: u32,
    pub derivation: Option<ExternalSigningDerivationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningPlanV2 {
    pub schema_version: u16,
    pub version: i32,
    pub lock_time: u32,
    pub inputs: Vec<ExternalSigningPlanInputV2>,
    pub outputs: Vec<ExternalSigningPlanOutputV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedExternalSigningRequestV2 {
    pub schema_version: u16,
    pub prepared_psbt_base64: String,
    pub requirements: ExternalSigningRequirementsV2,
    pub signing_plan: ExternalSigningPlanV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrepareExternalSigningErrorV2 {
    PreparationFailed { message: String },
    RequirementsInvalid { message: String },
    CapabilityRejected {
        requirements: ExternalSigningRequirementsV2,
        compatibility: ExternalSignerCompatibilityV2,
    },
}

impl fmt::Display for PrepareExternalSigningErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreparationFailed { message } => write!(f, "PSBT preparation failed: {message}"),
            Self::RequirementsInvalid { message } => {
                write!(f, "signing requirements are invalid: {message}")
            }
            Self::CapabilityRejected { compatibility, .. } => {
                if let Some(rejection) = compatibility.rejections.first() {
                    write!(f, "signer rejected: {rejection}")
                } else {
                    write!(f, "signer rejected without a reason")
                }
            }
        }
    }
}

impl std::error::Error for PrepareExternalSigningErrorV2 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningPlanOutputV1 {
    pub index: usize,
    pub amount_sats: String,
    pub script_pubkey_hex: String,
    pub output_type: ExternalSigningOutputTypeV1,
    pub address: Option<String>,
    pub op_return_data_hex: Option<String>,
    pub derivation: Option<ExternalSigningDerivationV1>,
}

fn input_script_pubkey(
    psbt: &Psbt,
    input_index: usize,
) -> Result<&Script, RequirementsDerivationError> {
    let input = &psbt.inputs[input_index];
    if let Some(txout) = &input.witness_utxo {
        return Ok(txout.script_pubkey.as_script());
    }

    let Some(previous_tx) = &input.non_witness_utxo else {
        return Err(RequirementsDerivationError::MissingPrevout { input_index });
    };
    let vout = psbt.unsigned_tx.input[input_index].previous_output.vout;
    previous_tx
        .output
        .get(vout as usize)
        .map(|txout| txout.script_pubkey.as_script())
        .ok_or(RequirementsDerivationError::MissingPreviousOutput { input_index, vout })
}

fn classify_input(psbt: &Psbt, input_index: usize, script: &Script) -> ExternalSigningInputTypeV1 {
    if script.is_p2pkh() {
        ExternalSigningInputTypeV1::P2pkh
    } else if script.is_p2sh() {
        ExternalSigningInputTypeV1::P2sh
    } else if script.is_p2wpkh() {
        ExternalSigningInputTypeV1::P2wpkh
    } else if script.is_p2wsh() {
        ExternalSigningInputTypeV1::P2wsh
    } else if script.is_p2tr() {
        let input = &psbt.inputs[input_index];
        if input.tap_scripts.is_empty() && input.tap_script_sigs.is_empty() {
            ExternalSigningInputTypeV1::P2trKeyPath
        } else {
            ExternalSigningInputTypeV1::P2trScriptPath
        }
    } else {
        ExternalSigningInputTypeV1::ArbitraryScript
    }
}

fn is_single_push_op_return(script: &Script) -> bool {
    let bytes = script.as_bytes();
    let Some(tail) = bytes.get(1..) else {
        return false;
    };
    let mut instructions = Script::from_bytes(tail).instructions();
    matches!(instructions.next(), Some(Ok(Instruction::PushBytes(_))))
        && instructions.next().is_none()
}

/// Classify an exact output script, recognizing the Runes `OP_RETURN OP_13`
/// envelope before ordinary push-data `OP_RETURN` outputs.
#[must_use]
pub fn classify_external_signing_output(script: &Script) -> ExternalSigningOutputTypeV1 {
    if script.is_p2pkh() {
        ExternalSigningOutputTypeV1::P2pkh
    } else if script.is_p2sh() {
        ExternalSigningOutputTypeV1::P2sh
    } else if script.is_p2wpkh() {
        ExternalSigningOutputTypeV1::P2wpkh
    } else if script.is_p2wsh() {
        ExternalSigningOutputTypeV1::P2wsh
    } else if script.is_p2tr() {
        ExternalSigningOutputTypeV1::P2tr
    } else if script.as_bytes().starts_with(&[0x6a, 0x5d]) {
        ExternalSigningOutputTypeV1::Runestone
    } else if script.is_op_return() && is_single_push_op_return(script) {
        ExternalSigningOutputTypeV1::OpReturnPushData
    } else {
        ExternalSigningOutputTypeV1::ArbitraryScript
    }
}

/// Derive V2 requirements while preserving the script-family/sighash
/// correlation for every input Zinc asks the signer to sign.
pub fn derive_external_signing_requirements_v2(
    psbt: &Psbt,
    required_input_indices: Option<&[usize]>,
) -> Result<ExternalSigningRequirementsV2, RequirementsDerivationError> {
    let input_count = psbt.inputs.len();
    let required_input_indices =
        required_input_indices.map_or_else(|| (0..input_count).collect(), <[usize]>::to_vec);

    let mut seen = BTreeSet::new();
    let mut required_inputs = Vec::with_capacity(required_input_indices.len());
    for &index in &required_input_indices {
        if index >= input_count {
            return Err(RequirementsDerivationError::RequiredInputOutOfBounds {
                input_index: index,
                input_count,
            });
        }
        if !seen.insert(index) {
            return Err(RequirementsDerivationError::DuplicateRequiredInput { input_index: index });
        }
        let script = input_script_pubkey(psbt, index)?;
        let input_type = classify_input(psbt, index, script);
        let default_sighash_type = match input_type {
            ExternalSigningInputTypeV1::P2trKeyPath
            | ExternalSigningInputTypeV1::P2trScriptPath => 0,
            _ => 1,
        };
        let sighash_type = psbt.inputs[index]
            .sighash_type
            .map_or(default_sighash_type, bitcoin::psbt::PsbtSighashType::to_u32);
        required_inputs.push(ExternalSigningInputRequirementV2 {
            index,
            input_type,
            sighash_type,
        });
    }

    let output_types = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|txout| classify_external_signing_output(txout.script_pubkey.as_script()))
        .collect();
    let requires_selective_signing = required_input_indices.len() != input_count;

    Ok(ExternalSigningRequirementsV2 {
        schema_version: EXTERNAL_SIGNING_SCHEMA_V2,
        required_inputs,
        output_types,
        input_count,
        output_count: psbt.unsigned_tx.output.len(),
        has_external_inputs: requires_selective_signing,
        requires_selective_signing,
    })
}

fn key_source_to_derivation(
    key_source: &bitcoin::bip32::KeySource,
) -> ExternalSigningDerivationV1 {
    let rendered_path = key_source.1.to_string();
    ExternalSigningDerivationV1 {
        master_fingerprint_hex: key_source.0.to_string().to_lowercase(),
        path: if rendered_path == "m" || rendered_path.starts_with("m/") {
            rendered_path
        } else {
            format!("m/{rendered_path}")
        },
    }
}

fn input_derivation(
    psbt: &Psbt,
    input_index: usize,
    input_type: ExternalSigningInputTypeV1,
) -> Option<ExternalSigningDerivationV1> {
    let input = &psbt.inputs[input_index];
    match input_type {
        ExternalSigningInputTypeV1::P2trKeyPath => input
            .tap_key_origins
            .values()
            .find(|(leaf_hashes, _)| leaf_hashes.is_empty())
            .map(|(_, key_source)| key_source_to_derivation(key_source)),
        _ => input
            .bip32_derivation
            .values()
            .next()
            .map(key_source_to_derivation),
    }
}

fn output_derivation(
    output: &bitcoin::psbt::Output,
) -> Option<ExternalSigningDerivationV1> {
    output
        .tap_key_origins
        .values()
        .find(|(leaf_hashes, _)| leaf_hashes.is_empty())
        .map(|(_, key_source)| key_source_to_derivation(key_source))
        .or_else(|| {
            output
                .bip32_derivation
                .values()
                .next()
                .map(key_source_to_derivation)
        })
}

fn single_push_op_return_data(script: &Script) -> Option<String> {
    if !is_single_push_op_return(script) {
        return None;
    }
    let mut instructions = script.instructions();
    let _op_return = instructions.next()?;
    match instructions.next()? {
        Ok(Instruction::PushBytes(bytes)) => Some(hex::encode(bytes.as_bytes())),
        _ => None,
    }
}

/// Build a V2 transport-neutral plan whose inputs carry the exact effective
/// sighash Zinc validated for their script family.
pub fn derive_external_signing_plan_v2(
    psbt: &Psbt,
    network: Network,
) -> Result<ExternalSigningPlanV2, RequirementsDerivationError> {
    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let script = input_script_pubkey(psbt, index)?;
        let input_type = classify_input(psbt, index, script);
        let amount = if let Some(txout) = &psbt.inputs[index].witness_utxo {
            txout.value
        } else {
            let previous_tx = psbt.inputs[index]
                .non_witness_utxo
                .as_ref()
                .ok_or(RequirementsDerivationError::MissingPrevout { input_index: index })?;
            previous_tx
                .output
                .get(txin.previous_output.vout as usize)
                .ok_or(RequirementsDerivationError::MissingPreviousOutput {
                    input_index: index,
                    vout: txin.previous_output.vout,
                })?
                .value
        };
        let default_sighash_type = match input_type {
                ExternalSigningInputTypeV1::P2trKeyPath
                | ExternalSigningInputTypeV1::P2trScriptPath => 0,
                _ => 1,
        };
        let sighash_type = psbt.inputs[index]
            .sighash_type
            .map_or(default_sighash_type, bitcoin::psbt::PsbtSighashType::to_u32);
        inputs.push(ExternalSigningPlanInputV2 {
            index,
            prev_hash: txin.previous_output.txid.to_string(),
            prev_index: txin.previous_output.vout,
            amount_sats: amount.to_sat().to_string(),
            sequence: txin.sequence.to_consensus_u32(),
            script_pubkey_hex: hex::encode(script.as_bytes()),
            input_type,
            sighash_type,
            derivation: input_derivation(psbt, index, input_type),
        });
    }
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .map(|(index, txout)| ExternalSigningPlanOutputV1 {
            index,
            amount_sats: txout.value.to_sat().to_string(),
            script_pubkey_hex: hex::encode(txout.script_pubkey.as_bytes()),
            output_type: classify_external_signing_output(txout.script_pubkey.as_script()),
            address: Address::from_script(txout.script_pubkey.as_script(), network)
                .ok()
                .map(|address| address.to_string()),
            op_return_data_hex: single_push_op_return_data(txout.script_pubkey.as_script()),
            derivation: output_derivation(&psbt.outputs[index]),
        })
        .collect();

    Ok(ExternalSigningPlanV2 {
        schema_version: EXTERNAL_SIGNING_SCHEMA_V2,
        version: psbt.unsigned_tx.version.0,
        lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
        inputs,
        outputs,
    })
}

fn rejection_v2(
    code: CapabilityRejectionCodeV2,
    capability: impl Into<String>,
    message: impl Into<String>,
) -> CapabilityRejectionV2 {
    CapabilityRejectionV2 {
        code,
        capability: capability.into(),
        message: message.into(),
        input_index: None,
        input_type: None,
        required_sighash_type: None,
        supported_sighash_types: None,
    }
}

/// Compare exact per-input requirements with V2 signer policies.
#[must_use]
pub fn check_external_signer_compatibility_v2(
    requirements: &ExternalSigningRequirementsV2,
    capabilities: &ExternalSignerCapabilitiesV2,
) -> ExternalSignerCompatibilityV2 {
    let mut rejections = Vec::new();
    if requirements.schema_version != EXTERNAL_SIGNING_SCHEMA_V2
        || capabilities.schema_version != EXTERNAL_SIGNING_SCHEMA_V2
    {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::SchemaVersionUnsupported,
            "schema.external_signing_v2",
            format!(
                "{} cannot negotiate external-signing schema versions requirements={} capabilities={}",
                capabilities.signer, requirements.schema_version, capabilities.schema_version
            ),
        ));
        return ExternalSignerCompatibilityV2 { compatible: false, rejections };
    }

    for required in &requirements.required_inputs {
        let Some(policy) = capabilities
            .input_signing_policies
            .iter()
            .find(|policy| policy.input_type == required.input_type)
        else {
            let mut rejection = rejection_v2(
                CapabilityRejectionCodeV2::CapabilityUnsupported,
                required.input_type.capability_key(),
                format!(
                    "{} cannot sign {:?} input #{}",
                    capabilities.signer, required.input_type, required.index
                ),
            );
            rejection.input_index = Some(required.index);
            rejection.input_type = Some(required.input_type);
            rejections.push(rejection);
            continue;
        };

        if !policy.supported_sighash_types.contains(&required.sighash_type) {
            let mut rejection = rejection_v2(
                CapabilityRejectionCodeV2::SighashUnsupportedForInput,
                format!("input.{}.sighash", required.index),
                format!(
                    "{} cannot sign {:?} input #{} with sighash value {}",
                    capabilities.signer,
                    required.input_type,
                    required.index,
                    required.sighash_type
                ),
            );
            rejection.input_index = Some(required.index);
            rejection.input_type = Some(required.input_type);
            rejection.required_sighash_type = Some(required.sighash_type);
            rejection.supported_sighash_types = Some(policy.supported_sighash_types.clone());
            rejections.push(rejection);
        }
    }

    for output_type in requirements
        .output_types
        .difference(&capabilities.supported_output_types)
    {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::TransactionNotRepresentable,
            output_type.capability_key(),
            format!(
                "{} cannot represent {output_type:?} outputs without changing the transaction",
                capabilities.signer
            ),
        ));
    }
    if requirements.has_external_inputs && !capabilities.supports_external_inputs {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::CapabilityUnsupported,
            "transaction.external_inputs",
            format!("{} cannot safely process external inputs", capabilities.signer),
        ));
    }
    if requirements.requires_selective_signing && !capabilities.supports_selective_signing {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::CapabilityUnsupported,
            "signing.selective_inputs",
            format!(
                "{} cannot restrict signing to the requested inputs",
                capabilities.signer
            ),
        ));
    }
    if capabilities
        .limits
        .max_inputs
        .is_some_and(|max| requirements.input_count > max)
    {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::DeviceLimitExceeded,
            "limits.inputs",
            format!(
                "{} supports at most {} inputs; transaction has {}",
                capabilities.signer,
                capabilities.limits.max_inputs.unwrap_or_default(),
                requirements.input_count
            ),
        ));
    }
    if capabilities
        .limits
        .max_outputs
        .is_some_and(|max| requirements.output_count > max)
    {
        rejections.push(rejection_v2(
            CapabilityRejectionCodeV2::DeviceLimitExceeded,
            "limits.outputs",
            format!(
                "{} supports at most {} outputs; transaction has {}",
                capabilities.signer,
                capabilities.limits.max_outputs.unwrap_or_default(),
                requirements.output_count
            ),
        ));
    }

    ExternalSignerCompatibilityV2 {
        compatible: rejections.is_empty(),
        rejections,
    }
}
