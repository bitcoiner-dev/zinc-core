//! Signed pairing and intent protocol primitives for decentralized agent approval flows.
//!
//! Phase 0 scope:
//! - Canonical serde models
//! - Deterministic domain-separated ids
//! - Schnorr signature helpers
//! - Structural validation for local fixtures and adapters

use crate::ZincError;
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

const VERSION_V1: u8 = 1;
const DOMAIN_PAIRING_REQUEST: &str = "zinc-pairing-request-v1";
const DOMAIN_PAIRING_ACK: &str = "zinc-pairing-ack-v1";
const DOMAIN_SIGN_INTENT: &str = "zinc-sign-intent-v1";
const DOMAIN_SIGN_INTENT_RECEIPT: &str = "zinc-sign-intent-receipt-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignIntentActionV1 {
    BuildBuyerOffer,
    SignSellerInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPolicyV1 {
    pub allowed_actions: Vec<SignIntentActionV1>,
    pub max_sats_per_intent: Option<u64>,
    pub daily_spend_limit_sats: Option<u64>,
    pub max_fee_rate_sat_vb: Option<u64>,
    pub allowed_networks: Vec<String>,
}

impl CapabilityPolicyV1 {
    fn validate(&self) -> Result<(), ZincError> {
        if self.allowed_actions.is_empty() {
            return Err(ZincError::OfferError(
                "capability policy must include at least one allowed action".to_string(),
            ));
        }

        let mut action_set = HashSet::new();
        for action in &self.allowed_actions {
            if !action_set.insert(*action) {
                return Err(ZincError::OfferError(
                    "capability policy contains duplicate allowed actions".to_string(),
                ));
            }
        }

        if self.allowed_networks.is_empty() {
            return Err(ZincError::OfferError(
                "capability policy must include at least one allowed network".to_string(),
            ));
        }

        let mut network_set = HashSet::new();
        for network in &self.allowed_networks {
            ensure_non_empty("capability network", network)?;
            let normalized = normalize_network(network);
            if !is_supported_network(&normalized) {
                return Err(ZincError::OfferError(format!(
                    "unsupported capability network `{network}`"
                )));
            }
            if !network_set.insert(normalized) {
                return Err(ZincError::OfferError(
                    "capability policy contains duplicate networks".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequestV1 {
    pub version: u8,
    pub agent_pubkey_hex: String,
    pub challenge_nonce: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    #[serde(default)]
    pub relays: Vec<String>,
    pub requested_capabilities: CapabilityPolicyV1,
}

impl PairingRequestV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        validate_pubkey_hex("pairing request agent_pubkey_hex", &self.agent_pubkey_hex)?;
        validate_nonce("pairing request challenge_nonce", &self.challenge_nonce)?;
        validate_expiry_window(self.created_at_unix, self.expires_at_unix)?;
        validate_unique_relays(&self.relays)?;
        self.requested_capabilities.validate()
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn pairing_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_PAIRING_REQUEST, &self.canonical_json()?)
    }

    pub fn pairing_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.pairing_id_digest()?))
    }

    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        sign_payload_with_expected_pubkey(
            secret_key_hex,
            &self.agent_pubkey_hex,
            DOMAIN_PAIRING_REQUEST,
            &self.canonical_json()?,
        )
    }

    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        verify_payload_signature(
            &self.agent_pubkey_hex,
            signature_hex,
            DOMAIN_PAIRING_REQUEST,
            &self.canonical_json()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingAckDecisionV1 {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingAckV1 {
    pub version: u8,
    pub pairing_id: String,
    pub challenge_nonce: String,
    pub agent_pubkey_hex: String,
    pub wallet_pubkey_hex: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub decision: PairingAckDecisionV1,
    pub granted_capabilities: Option<CapabilityPolicyV1>,
    pub rejection_reason: Option<String>,
}

impl PairingAckV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        validate_hex64("pairing ack pairing_id", &self.pairing_id)?;
        validate_nonce("pairing ack challenge_nonce", &self.challenge_nonce)?;
        validate_pubkey_hex("pairing ack agent_pubkey_hex", &self.agent_pubkey_hex)?;
        validate_pubkey_hex("pairing ack wallet_pubkey_hex", &self.wallet_pubkey_hex)?;
        validate_expiry_window(self.created_at_unix, self.expires_at_unix)?;

        match self.decision {
            PairingAckDecisionV1::Approved => {
                if self.granted_capabilities.is_none() {
                    return Err(ZincError::OfferError(
                        "approved pairing ack must include granted_capabilities".to_string(),
                    ));
                }
                if self.rejection_reason.is_some() {
                    return Err(ZincError::OfferError(
                        "approved pairing ack must not include rejection_reason".to_string(),
                    ));
                }
            }
            PairingAckDecisionV1::Rejected => {
                if self.granted_capabilities.is_some() {
                    return Err(ZincError::OfferError(
                        "rejected pairing ack must not include granted_capabilities".to_string(),
                    ));
                }
            }
        }

        if let Some(capabilities) = &self.granted_capabilities {
            capabilities.validate()?;
        }

        if let Some(reason) = &self.rejection_reason {
            ensure_non_empty("pairing ack rejection_reason", reason)?;
        }

        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn ack_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_PAIRING_ACK, &self.canonical_json()?)
    }

    pub fn ack_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.ack_id_digest()?))
    }

    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        sign_payload_with_expected_pubkey(
            secret_key_hex,
            &self.wallet_pubkey_hex,
            DOMAIN_PAIRING_ACK,
            &self.canonical_json()?,
        )
    }

    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        verify_payload_signature(
            &self.wallet_pubkey_hex,
            signature_hex,
            DOMAIN_PAIRING_ACK,
            &self.canonical_json()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildBuyerOfferIntentV1 {
    pub inscription_id: String,
    pub seller_outpoint: String,
    pub ask_sats: u64,
    pub fee_rate_sat_vb: u64,
}

impl BuildBuyerOfferIntentV1 {
    fn validate(&self) -> Result<(), ZincError> {
        ensure_non_empty("build buyer offer inscription_id", &self.inscription_id)?;
        ensure_non_empty("build buyer offer seller_outpoint", &self.seller_outpoint)?;
        if self.ask_sats == 0 {
            return Err(ZincError::OfferError(
                "build buyer offer ask_sats must be > 0".to_string(),
            ));
        }
        if self.fee_rate_sat_vb == 0 {
            return Err(ZincError::OfferError(
                "build buyer offer fee_rate_sat_vb must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignSellerInputIntentV1 {
    pub offer_id: String,
    pub offer_psbt_base64: String,
    pub expected_seller_outpoint: String,
    pub expected_ask_sats: u64,
}

impl SignSellerInputIntentV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_hex64("sign seller input offer_id", &self.offer_id)?;
        ensure_non_empty(
            "sign seller input offer_psbt_base64",
            &self.offer_psbt_base64,
        )?;
        ensure_non_empty(
            "sign seller input expected_seller_outpoint",
            &self.expected_seller_outpoint,
        )?;
        if self.expected_ask_sats == 0 {
            return Err(ZincError::OfferError(
                "sign seller input expected_ask_sats must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "params", rename_all = "camelCase")]
pub enum SignIntentPayloadV1 {
    BuildBuyerOffer(BuildBuyerOfferIntentV1),
    SignSellerInput(SignSellerInputIntentV1),
}

impl SignIntentPayloadV1 {
    fn validate(&self) -> Result<(), ZincError> {
        match self {
            Self::BuildBuyerOffer(payload) => payload.validate(),
            Self::SignSellerInput(payload) => payload.validate(),
        }
    }

    pub fn action(&self) -> SignIntentActionV1 {
        match self {
            Self::BuildBuyerOffer(_) => SignIntentActionV1::BuildBuyerOffer,
            Self::SignSellerInput(_) => SignIntentActionV1::SignSellerInput,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignIntentV1 {
    pub version: u8,
    pub pairing_id: String,
    pub agent_pubkey_hex: String,
    pub wallet_pubkey_hex: String,
    pub network: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub nonce: u64,
    pub payload: SignIntentPayloadV1,
}

impl SignIntentV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        validate_hex64("sign intent pairing_id", &self.pairing_id)?;
        validate_pubkey_hex("sign intent agent_pubkey_hex", &self.agent_pubkey_hex)?;
        validate_pubkey_hex("sign intent wallet_pubkey_hex", &self.wallet_pubkey_hex)?;
        ensure_non_empty("sign intent network", &self.network)?;

        let normalized_network = normalize_network(&self.network);
        if !is_supported_network(&normalized_network) {
            return Err(ZincError::OfferError(format!(
                "unsupported sign intent network `{}`",
                self.network
            )));
        }

        validate_expiry_window(self.created_at_unix, self.expires_at_unix)?;
        self.payload.validate()
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn intent_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_SIGN_INTENT, &self.canonical_json()?)
    }

    pub fn intent_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.intent_id_digest()?))
    }

    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        sign_payload_with_expected_pubkey(
            secret_key_hex,
            &self.agent_pubkey_hex,
            DOMAIN_SIGN_INTENT,
            &self.canonical_json()?,
        )
    }

    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        verify_payload_signature(
            &self.agent_pubkey_hex,
            signature_hex,
            DOMAIN_SIGN_INTENT,
            &self.canonical_json()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignIntentReceiptStatusV1 {
    Approved,
    Rejected,
    Expired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignIntentReceiptV1 {
    pub version: u8,
    pub intent_id: String,
    pub pairing_id: String,
    pub signer_pubkey_hex: String,
    pub created_at_unix: i64,
    pub status: SignIntentReceiptStatusV1,
    pub signed_psbt_base64: Option<String>,
    pub artifact_json: Option<String>,
    pub error_message: Option<String>,
}

impl SignIntentReceiptV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        validate_hex64("sign intent receipt intent_id", &self.intent_id)?;
        validate_hex64("sign intent receipt pairing_id", &self.pairing_id)?;
        validate_pubkey_hex(
            "sign intent receipt signer_pubkey_hex",
            &self.signer_pubkey_hex,
        )?;

        match self.status {
            SignIntentReceiptStatusV1::Approved => {
                if self.signed_psbt_base64.is_none() && self.artifact_json.is_none() {
                    return Err(ZincError::OfferError(
                        "approved sign intent receipt must include signed_psbt_base64 or artifact_json"
                            .to_string(),
                    ));
                }
            }
            SignIntentReceiptStatusV1::Rejected
            | SignIntentReceiptStatusV1::Expired
            | SignIntentReceiptStatusV1::Failed => {}
        }

        if let Some(psbt) = &self.signed_psbt_base64 {
            ensure_non_empty("sign intent receipt signed_psbt_base64", psbt)?;
        }
        if let Some(artifact) = &self.artifact_json {
            ensure_non_empty("sign intent receipt artifact_json", artifact)?;
        }
        if let Some(message) = &self.error_message {
            ensure_non_empty("sign intent receipt error_message", message)?;
        }

        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn receipt_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_SIGN_INTENT_RECEIPT, &self.canonical_json()?)
    }

    pub fn receipt_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.receipt_id_digest()?))
    }

    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        sign_payload_with_expected_pubkey(
            secret_key_hex,
            &self.signer_pubkey_hex,
            DOMAIN_SIGN_INTENT_RECEIPT,
            &self.canonical_json()?,
        )
    }

    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        verify_payload_signature(
            &self.signer_pubkey_hex,
            signature_hex,
            DOMAIN_SIGN_INTENT_RECEIPT,
            &self.canonical_json()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPairingRequestV1 {
    pub request: PairingRequestV1,
    pub signature_hex: String,
}

impl SignedPairingRequestV1 {
    pub fn new(request: PairingRequestV1, secret_key_hex: &str) -> Result<Self, ZincError> {
        let signature_hex = request.sign_schnorr_hex(secret_key_hex)?;
        Ok(Self {
            request,
            signature_hex,
        })
    }

    pub fn verify(&self) -> Result<(), ZincError> {
        self.request.verify_schnorr_hex(&self.signature_hex)
    }

    pub fn pairing_id_hex(&self) -> Result<String, ZincError> {
        self.request.pairing_id_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPairingAckV1 {
    pub ack: PairingAckV1,
    pub signature_hex: String,
}

impl SignedPairingAckV1 {
    pub fn new(ack: PairingAckV1, secret_key_hex: &str) -> Result<Self, ZincError> {
        let signature_hex = ack.sign_schnorr_hex(secret_key_hex)?;
        Ok(Self { ack, signature_hex })
    }

    pub fn verify(&self) -> Result<(), ZincError> {
        self.ack.verify_schnorr_hex(&self.signature_hex)
    }

    pub fn ack_id_hex(&self) -> Result<String, ZincError> {
        self.ack.ack_id_hex()
    }
}

pub fn build_signed_pairing_ack(
    signed_request: &SignedPairingRequestV1,
    wallet_secret_key_hex: &str,
    now_unix: i64,
    ack_ttl_secs: i64,
) -> Result<SignedPairingAckV1, ZincError> {
    build_signed_pairing_ack_with_granted(
        signed_request,
        wallet_secret_key_hex,
        now_unix,
        ack_ttl_secs,
        None,
    )
}

pub fn build_signed_pairing_ack_with_granted(
    signed_request: &SignedPairingRequestV1,
    wallet_secret_key_hex: &str,
    now_unix: i64,
    ack_ttl_secs: i64,
    granted_capabilities: Option<CapabilityPolicyV1>,
) -> Result<SignedPairingAckV1, ZincError> {
    if ack_ttl_secs <= 0 {
        return Err(ZincError::OfferError(
            "pairing ack ttl must be greater than zero seconds".to_string(),
        ));
    }

    signed_request.verify()?;
    let request = &signed_request.request;
    if now_unix > request.expires_at_unix {
        return Err(ZincError::OfferError(
            "pairing request expired before ack creation".to_string(),
        ));
    }

    let created_at_unix = now_unix;
    let ttl_expires_at_unix = created_at_unix.checked_add(ack_ttl_secs).ok_or_else(|| {
        ZincError::OfferError("pairing ack expiry overflowed unix range".to_string())
    })?;
    let expires_at_unix = ttl_expires_at_unix.min(request.expires_at_unix);
    if expires_at_unix <= created_at_unix {
        return Err(ZincError::OfferError(
            "pairing ack expires_at_unix must be greater than created_at_unix".to_string(),
        ));
    }

    let pairing_id = signed_request.pairing_id_hex()?;
    let wallet_pubkey_hex = pubkey_hex_from_secret_key(wallet_secret_key_hex)?;
    let granted_capabilities =
        granted_capabilities.unwrap_or_else(|| request.requested_capabilities.clone());

    let ack = PairingAckV1 {
        version: VERSION_V1,
        pairing_id,
        challenge_nonce: request.challenge_nonce.clone(),
        agent_pubkey_hex: request.agent_pubkey_hex.clone(),
        wallet_pubkey_hex,
        created_at_unix,
        expires_at_unix,
        decision: PairingAckDecisionV1::Approved,
        granted_capabilities: Some(granted_capabilities),
        rejection_reason: None,
    };

    let signed_ack = SignedPairingAckV1::new(ack, wallet_secret_key_hex)?;
    verify_pairing_approval(signed_request, &signed_ack, now_unix)?;
    Ok(signed_ack)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSignIntentV1 {
    pub intent: SignIntentV1,
    pub signature_hex: String,
}

impl SignedSignIntentV1 {
    pub fn new(intent: SignIntentV1, secret_key_hex: &str) -> Result<Self, ZincError> {
        let signature_hex = intent.sign_schnorr_hex(secret_key_hex)?;
        Ok(Self {
            intent,
            signature_hex,
        })
    }

    pub fn verify(&self) -> Result<(), ZincError> {
        self.intent.verify_schnorr_hex(&self.signature_hex)
    }

    pub fn intent_id_hex(&self) -> Result<String, ZincError> {
        self.intent.intent_id_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSignIntentReceiptV1 {
    pub receipt: SignIntentReceiptV1,
    pub signature_hex: String,
}

impl SignedSignIntentReceiptV1 {
    pub fn new(receipt: SignIntentReceiptV1, secret_key_hex: &str) -> Result<Self, ZincError> {
        let signature_hex = receipt.sign_schnorr_hex(secret_key_hex)?;
        Ok(Self {
            receipt,
            signature_hex,
        })
    }

    pub fn verify(&self) -> Result<(), ZincError> {
        self.receipt.verify_schnorr_hex(&self.signature_hex)
    }

    pub fn receipt_id_hex(&self) -> Result<String, ZincError> {
        self.receipt.receipt_id_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingLinkApprovalV1 {
    pub pairing_id: String,
    pub agent_pubkey_hex: String,
    pub wallet_pubkey_hex: String,
    pub granted_capabilities: CapabilityPolicyV1,
    pub request_expires_at_unix: i64,
    pub ack_expires_at_unix: i64,
}

pub fn verify_pairing_approval(
    signed_request: &SignedPairingRequestV1,
    signed_ack: &SignedPairingAckV1,
    now_unix: i64,
) -> Result<PairingLinkApprovalV1, ZincError> {
    signed_request.verify()?;
    signed_ack.verify()?;

    let request = &signed_request.request;
    let ack = &signed_ack.ack;

    let pairing_id = signed_request.pairing_id_hex()?;
    if ack.pairing_id != pairing_id {
        return Err(ZincError::OfferError(
            "pairing ack pairing_id does not match pairing request".to_string(),
        ));
    }

    if ack.challenge_nonce != request.challenge_nonce {
        return Err(ZincError::OfferError(
            "pairing ack challenge_nonce does not match pairing request".to_string(),
        ));
    }

    if ack.agent_pubkey_hex != request.agent_pubkey_hex {
        return Err(ZincError::OfferError(
            "pairing ack agent_pubkey_hex does not match pairing request".to_string(),
        ));
    }

    if now_unix > request.expires_at_unix {
        return Err(ZincError::OfferError(
            "pairing request expired before ack verification".to_string(),
        ));
    }

    if now_unix > ack.expires_at_unix {
        return Err(ZincError::OfferError(
            "pairing ack expired before verification".to_string(),
        ));
    }

    if !matches!(ack.decision, PairingAckDecisionV1::Approved) {
        return Err(ZincError::OfferError(
            "pairing ack decision is not approved".to_string(),
        ));
    }

    let granted = ack.granted_capabilities.clone().ok_or_else(|| {
        ZincError::OfferError("approved pairing ack missing granted_capabilities".to_string())
    })?;
    validate_granted_capabilities_subset(&request.requested_capabilities, &granted)?;

    Ok(PairingLinkApprovalV1 {
        pairing_id,
        agent_pubkey_hex: request.agent_pubkey_hex.clone(),
        wallet_pubkey_hex: ack.wallet_pubkey_hex.clone(),
        granted_capabilities: granted,
        request_expires_at_unix: request.expires_at_unix,
        ack_expires_at_unix: ack.expires_at_unix,
    })
}

pub fn verify_pairing_approval_json(
    signed_request_json: &str,
    signed_ack_json: &str,
    now_unix: i64,
) -> Result<PairingLinkApprovalV1, ZincError> {
    let signed_request: SignedPairingRequestV1 = serde_json::from_str(signed_request_json)
        .map_err(|e| {
            ZincError::SerializationError(format!("invalid signed pairing request json: {e}"))
        })?;
    let signed_ack: SignedPairingAckV1 = serde_json::from_str(signed_ack_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed pairing ack json: {e}"))
    })?;
    verify_pairing_approval(&signed_request, &signed_ack, now_unix)
}

pub fn validate_signed_pairing_request_json(payload_json: &str) -> Result<String, ZincError> {
    let signed: SignedPairingRequestV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed pairing request json: {e}"))
    })?;
    signed.verify()?;
    signed.pairing_id_hex()
}

pub fn validate_signed_pairing_ack_json(payload_json: &str) -> Result<String, ZincError> {
    let signed: SignedPairingAckV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed pairing ack json: {e}"))
    })?;
    signed.verify()?;
    signed.ack_id_hex()
}

pub fn validate_signed_sign_intent_json(payload_json: &str) -> Result<String, ZincError> {
    let signed: SignedSignIntentV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed sign intent json: {e}"))
    })?;
    signed.verify()?;
    signed.intent_id_hex()
}

pub fn validate_signed_sign_intent_receipt_json(payload_json: &str) -> Result<String, ZincError> {
    let signed: SignedSignIntentReceiptV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed sign intent receipt json: {e}"))
    })?;
    signed.verify()?;
    signed.receipt_id_hex()
}

pub fn pubkey_hex_from_secret_key(secret_key_hex: &str) -> Result<String, ZincError> {
    let secret_key = SecretKey::from_str(secret_key_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;
    Ok(pubkey_hex_from_secret(&secret_key))
}

fn validate_version(version: u8) -> Result<(), ZincError> {
    if version != VERSION_V1 {
        return Err(ZincError::OfferError(format!(
            "unsupported protocol version {version}"
        )));
    }
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> Result<(), ZincError> {
    if value.trim().is_empty() {
        return Err(ZincError::OfferError(format!("{label} must not be empty")));
    }
    Ok(())
}

fn validate_nonce(label: &str, nonce: &str) -> Result<(), ZincError> {
    ensure_non_empty(label, nonce)?;
    if nonce.len() > 256 {
        return Err(ZincError::OfferError(format!(
            "{label} is too long (max 256 chars)"
        )));
    }
    Ok(())
}

fn validate_expiry_window(created_at_unix: i64, expires_at_unix: i64) -> Result<(), ZincError> {
    if expires_at_unix <= created_at_unix {
        return Err(ZincError::OfferError(
            "expires_at_unix must be greater than created_at_unix".to_string(),
        ));
    }
    Ok(())
}

fn validate_unique_relays(relays: &[String]) -> Result<(), ZincError> {
    let mut seen = HashSet::new();
    for relay in relays {
        ensure_non_empty("relay url", relay)?;
        if !seen.insert(relay.to_ascii_lowercase()) {
            return Err(ZincError::OfferError(
                "duplicate relay url in pairing request".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_granted_capabilities_subset(
    requested: &CapabilityPolicyV1,
    granted: &CapabilityPolicyV1,
) -> Result<(), ZincError> {
    requested.validate()?;
    granted.validate()?;

    let requested_actions: HashSet<SignIntentActionV1> =
        requested.allowed_actions.iter().copied().collect();
    for action in &granted.allowed_actions {
        if !requested_actions.contains(action) {
            return Err(ZincError::OfferError(format!(
                "granted capability action `{action:?}` was not requested"
            )));
        }
    }

    let requested_networks: HashSet<String> = requested
        .allowed_networks
        .iter()
        .map(|network| normalize_network(network))
        .collect();
    for network in &granted.allowed_networks {
        let normalized = normalize_network(network);
        if !requested_networks.contains(&normalized) {
            return Err(ZincError::OfferError(format!(
                "granted capability network `{network}` was not requested"
            )));
        }
    }

    validate_capability_limit(
        "max_sats_per_intent",
        requested.max_sats_per_intent,
        granted.max_sats_per_intent,
    )?;
    validate_capability_limit(
        "daily_spend_limit_sats",
        requested.daily_spend_limit_sats,
        granted.daily_spend_limit_sats,
    )?;
    validate_capability_limit(
        "max_fee_rate_sat_vb",
        requested.max_fee_rate_sat_vb,
        granted.max_fee_rate_sat_vb,
    )?;

    Ok(())
}

fn validate_capability_limit(
    label: &str,
    requested: Option<u64>,
    granted: Option<u64>,
) -> Result<(), ZincError> {
    match (requested, granted) {
        (Some(requested_limit), Some(granted_limit)) if granted_limit <= requested_limit => Ok(()),
        (Some(requested_limit), Some(granted_limit)) => Err(ZincError::OfferError(format!(
            "granted {label}={granted_limit} exceeds requested limit {requested_limit}"
        ))),
        (Some(_), None) => Err(ZincError::OfferError(format!(
            "granted {label} must be set because request set a limit"
        ))),
        (None, _) => Ok(()),
    }
}

fn validate_hex64(label: &str, value: &str) -> Result<(), ZincError> {
    if value.len() != 64 {
        return Err(ZincError::OfferError(format!(
            "{label} must be 64 hex characters"
        )));
    }
    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ZincError::OfferError(format!("{label} must be valid hex")));
    }
    Ok(())
}

fn validate_pubkey_hex(label: &str, value: &str) -> Result<(), ZincError> {
    ensure_non_empty(label, value)?;
    XOnlyPublicKey::from_str(value)
        .map_err(|e| ZincError::OfferError(format!("{label} is invalid: {e}")))?;
    Ok(())
}

fn normalize_network(network: &str) -> String {
    let lower = network.trim().to_ascii_lowercase();
    if lower == "bitcoin" {
        "mainnet".to_string()
    } else {
        lower
    }
}

fn is_supported_network(network: &str) -> bool {
    matches!(network, "mainnet" | "signet" | "testnet" | "regtest")
}

fn domain_separated_digest(domain: &str, canonical_payload: &[u8]) -> Result<[u8; 32], ZincError> {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical_payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0u8);
    bytes.extend_from_slice(canonical_payload);
    let digest = sha256::Hash::hash(&bytes);
    Ok(digest.to_byte_array())
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn pubkey_hex_from_secret(secret_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    xonly.to_string()
}

fn sign_payload_with_expected_pubkey(
    secret_key_hex: &str,
    expected_pubkey_hex: &str,
    domain: &str,
    canonical_payload: &[u8],
) -> Result<String, ZincError> {
    let secret_key = SecretKey::from_str(secret_key_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;

    let actual_pubkey_hex = pubkey_hex_from_secret(&secret_key);
    if actual_pubkey_hex != expected_pubkey_hex {
        return Err(ZincError::OfferError(format!(
            "secret key does not match expected pubkey {expected_pubkey_hex}"
        )));
    }

    let digest = domain_separated_digest(domain, canonical_payload)?;
    let message = Message::from_digest(digest);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(signature.to_string())
}

fn verify_payload_signature(
    pubkey_hex: &str,
    signature_hex: &str,
    domain: &str,
    canonical_payload: &[u8],
) -> Result<(), ZincError> {
    let pubkey = XOnlyPublicKey::from_str(pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid signature pubkey: {e}")))?;
    let signature = Signature::from_str(signature_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid schnorr signature: {e}")))?;
    let digest = domain_separated_digest(domain, canonical_payload)?;
    let message = Message::from_digest(digest);

    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &message, &pubkey)
        .map_err(|e| ZincError::OfferError(format!("signature verification failed: {e}")))
}
