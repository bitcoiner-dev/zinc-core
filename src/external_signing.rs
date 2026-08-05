//! Vendor-neutral capability negotiation for external signers.
//!
//! Zinc derives [`ExternalSigningRequirementsV1`] from the exact PSBT that will
//! be handed to a signer. A hardware-wallet adapter independently describes the
//! effective capabilities of its provider/model/firmware/transport combination
//! with [`ExternalSignerCapabilitiesV1`]. The matcher in this module is pure and
//! deny-by-default: every derived requirement must be explicitly supported.

use bitcoin::psbt::Psbt;
use bitcoin::script::{Instruction, Script};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Schema version used by all `V1` external-signing values.
pub const EXTERNAL_SIGNING_SCHEMA_V1: u16 = 1;

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

/// Requirements derived from the exact prepared PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSigningRequirementsV1 {
    pub schema_version: u16,
    pub required_input_indices: Vec<usize>,
    pub input_types: BTreeSet<ExternalSigningInputTypeV1>,
    pub output_types: BTreeSet<ExternalSigningOutputTypeV1>,
    /// Raw consensus sighash values required by inputs Zinc asks the signer to sign.
    pub sighash_types: BTreeSet<u32>,
    pub input_count: usize,
    pub output_count: usize,
    /// True when the PSBT contains inputs outside `required_input_indices`.
    pub has_external_inputs: bool,
    /// True when Zinc asks the signer to sign fewer than all transaction inputs.
    pub requires_selective_signing: bool,
}

/// Optional signer limits which can vary by model, firmware, or transport.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerLimitsV1 {
    pub max_inputs: Option<usize>,
    pub max_outputs: Option<usize>,
}

/// Effective capabilities supplied by a hardware-wallet adapter.
///
/// `signer` is an opaque diagnostic label such as
/// `"trezor:safe-5:2.8.1:webusb"`. `zinc-core` never branches on its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerCapabilitiesV1 {
    pub schema_version: u16,
    pub signer: String,
    pub supported_input_types: BTreeSet<ExternalSigningInputTypeV1>,
    pub supported_output_types: BTreeSet<ExternalSigningOutputTypeV1>,
    pub supported_sighash_types: BTreeSet<u32>,
    pub supports_external_inputs: bool,
    pub supports_selective_signing: bool,
    #[serde(default)]
    pub limits: ExternalSignerLimitsV1,
}

impl ExternalSignerCapabilitiesV1 {
    /// Start with an empty, deny-by-default capability set.
    #[must_use]
    pub fn deny_all(signer: impl Into<String>) -> Self {
        Self {
            schema_version: EXTERNAL_SIGNING_SCHEMA_V1,
            signer: signer.into(),
            supported_input_types: BTreeSet::new(),
            supported_output_types: BTreeSet::new(),
            supported_sighash_types: BTreeSet::new(),
            supports_external_inputs: false,
            supports_selective_signing: false,
            limits: ExternalSignerLimitsV1::default(),
        }
    }
}

/// Stable rejection categories suitable for RPC/UI handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRejectionCodeV1 {
    SchemaVersionUnsupported,
    CapabilityUnsupported,
    FirmwareTooOld,
    AdapterUnsupported,
    TransactionNotRepresentable,
    DeviceLimitExceeded,
}

/// A typed, user-presentable reason an external signer must not receive a PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRejectionV1 {
    pub code: CapabilityRejectionCodeV1,
    /// Stable capability key, for example `output.runestone`.
    pub capability: String,
    pub message: String,
}

impl fmt::Display for CapabilityRejectionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.capability, self.message)
    }
}

impl std::error::Error for CapabilityRejectionV1 {}

/// Complete compatibility result. An empty `rejections` list means compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSignerCompatibilityV1 {
    pub compatible: bool,
    pub rejections: Vec<CapabilityRejectionV1>,
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

/// Prepared PSBT plus its capability requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedExternalSigningRequestV1 {
    pub schema_version: u16,
    pub prepared_psbt_base64: String,
    pub requirements: ExternalSigningRequirementsV1,
}

/// Typed failure from the capability-enforced preparation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrepareExternalSigningErrorV1 {
    PreparationFailed {
        message: String,
    },
    RequirementsInvalid {
        message: String,
    },
    CapabilityRejected {
        requirements: ExternalSigningRequirementsV1,
        compatibility: ExternalSignerCompatibilityV1,
    },
}

impl fmt::Display for PrepareExternalSigningErrorV1 {
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

impl std::error::Error for PrepareExternalSigningErrorV1 {}

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

/// Derive signer requirements from the exact PSBT and requested signing scope.
///
/// `required_input_indices = None` means all inputs. Supplying a strict subset
/// records both selective signing and the presence of external inputs.
pub fn derive_external_signing_requirements(
    psbt: &Psbt,
    required_input_indices: Option<&[usize]>,
) -> Result<ExternalSigningRequirementsV1, RequirementsDerivationError> {
    let input_count = psbt.inputs.len();
    let required_input_indices =
        required_input_indices.map_or_else(|| (0..input_count).collect(), <[usize]>::to_vec);

    let mut seen = BTreeSet::new();
    for &input_index in &required_input_indices {
        if input_index >= input_count {
            return Err(RequirementsDerivationError::RequiredInputOutOfBounds {
                input_index,
                input_count,
            });
        }
        if !seen.insert(input_index) {
            return Err(RequirementsDerivationError::DuplicateRequiredInput { input_index });
        }
    }

    let mut input_types = BTreeSet::new();
    let mut sighash_types = BTreeSet::new();
    for &input_index in &required_input_indices {
        let script = input_script_pubkey(psbt, input_index)?;
        let input_type = classify_input(psbt, input_index, script);
        let default_sighash = match input_type {
            ExternalSigningInputTypeV1::P2trKeyPath
            | ExternalSigningInputTypeV1::P2trScriptPath => 0,
            _ => 1,
        };
        input_types.insert(input_type);
        sighash_types.insert(
            psbt.inputs[input_index]
                .sighash_type
                .map_or(default_sighash, bitcoin::psbt::PsbtSighashType::to_u32),
        );
    }

    let output_types = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|txout| classify_external_signing_output(txout.script_pubkey.as_script()))
        .collect();
    let requires_selective_signing = required_input_indices.len() != input_count;

    Ok(ExternalSigningRequirementsV1 {
        schema_version: EXTERNAL_SIGNING_SCHEMA_V1,
        required_input_indices,
        input_types,
        output_types,
        sighash_types,
        input_count,
        output_count: psbt.unsigned_tx.output.len(),
        has_external_inputs: requires_selective_signing,
        requires_selective_signing,
    })
}

fn rejection(
    code: CapabilityRejectionCodeV1,
    capability: impl Into<String>,
    message: impl Into<String>,
) -> CapabilityRejectionV1 {
    CapabilityRejectionV1 {
        code,
        capability: capability.into(),
        message: message.into(),
    }
}

fn append_limit_rejections(
    requirements: &ExternalSigningRequirementsV1,
    capabilities: &ExternalSignerCapabilitiesV1,
    rejections: &mut Vec<CapabilityRejectionV1>,
) {
    if capabilities
        .limits
        .max_inputs
        .is_some_and(|max| requirements.input_count > max)
    {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::DeviceLimitExceeded,
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
        rejections.push(rejection(
            CapabilityRejectionCodeV1::DeviceLimitExceeded,
            "limits.outputs",
            format!(
                "{} supports at most {} outputs; transaction has {}",
                capabilities.signer,
                capabilities.limits.max_outputs.unwrap_or_default(),
                requirements.output_count
            ),
        ));
    }
}

/// Compare requirements and effective signer capabilities without device I/O.
///
/// The result is deterministic and collects every incompatibility so a UI can
/// explain all blockers during preflight. The same function should be called
/// again immediately before dispatching the PSBT to the signer.
#[must_use]
pub fn check_external_signer_compatibility(
    requirements: &ExternalSigningRequirementsV1,
    capabilities: &ExternalSignerCapabilitiesV1,
) -> ExternalSignerCompatibilityV1 {
    let mut rejections = Vec::new();

    if requirements.schema_version != EXTERNAL_SIGNING_SCHEMA_V1
        || capabilities.schema_version != EXTERNAL_SIGNING_SCHEMA_V1
    {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::SchemaVersionUnsupported,
            "schema.external_signing_v1",
            format!(
                "{} cannot negotiate external-signing schema versions requirements={} capabilities={}",
                capabilities.signer, requirements.schema_version, capabilities.schema_version
            ),
        ));
        return ExternalSignerCompatibilityV1 {
            compatible: false,
            rejections,
        };
    }

    for input_type in requirements
        .input_types
        .difference(&capabilities.supported_input_types)
    {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::CapabilityUnsupported,
            input_type.capability_key(),
            format!("{} cannot sign {input_type:?} inputs", capabilities.signer),
        ));
    }
    for output_type in requirements
        .output_types
        .difference(&capabilities.supported_output_types)
    {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::CapabilityUnsupported,
            output_type.capability_key(),
            format!(
                "{} cannot represent {output_type:?} outputs without changing the transaction",
                capabilities.signer
            ),
        ));
    }
    for sighash in requirements
        .sighash_types
        .difference(&capabilities.supported_sighash_types)
    {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::CapabilityUnsupported,
            format!("sighash.{sighash}"),
            format!(
                "{} does not support sighash value {sighash}",
                capabilities.signer
            ),
        ));
    }

    if requirements.has_external_inputs && !capabilities.supports_external_inputs {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::CapabilityUnsupported,
            "transaction.external_inputs",
            format!(
                "{} cannot safely process external inputs",
                capabilities.signer
            ),
        ));
    }
    if requirements.requires_selective_signing && !capabilities.supports_selective_signing {
        rejections.push(rejection(
            CapabilityRejectionCodeV1::CapabilityUnsupported,
            "signing.selective_inputs",
            format!(
                "{} cannot restrict signing to the requested inputs",
                capabilities.signer
            ),
        ));
    }
    append_limit_rejections(requirements, capabilities, &mut rejections);

    ExternalSignerCompatibilityV1 {
        compatible: rejections.is_empty(),
        rejections,
    }
}

/// Return the first deterministic incompatibility, if any.
pub fn require_external_signer_capabilities(
    requirements: &ExternalSigningRequirementsV1,
    capabilities: &ExternalSignerCapabilitiesV1,
) -> Result<(), CapabilityRejectionV1> {
    let report = check_external_signer_compatibility(requirements, capabilities);
    report.rejections.into_iter().next().map_or(Ok(()), Err)
}
