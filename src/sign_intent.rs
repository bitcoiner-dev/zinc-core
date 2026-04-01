//! Signed pairing and intent protocol primitives for decentralized agent approval flows.
//!
//! Phase 0 scope:
//! - Canonical serde models
//! - Deterministic domain-separated ids
//! - Schnorr signature helpers
//! - Structural validation for local fixtures and adapters

use crate::ZincError;
use base64::Engine;
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::psbt::{Input as PsbtInput, Psbt};
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::OutPoint;
use getrandom::getrandom;
use nostr::nips::nip44;
use nostr::{PublicKey as NostrPublicKey, SecretKey as NostrSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

const VERSION_V1: u8 = 1;
const DOMAIN_PAIRING_REQUEST: &str = "zinc-pairing-request-v1";
const DOMAIN_PAIRING_ACK: &str = "zinc-pairing-ack-v1";
const DOMAIN_PAIRING_ACK_ENVELOPE: &str = "zinc-pairing-ack-envelope-v1";
const DOMAIN_PAIRING_TAG_HASH: &str = "zinc-pairing-tag-hash-v1";
const DOMAIN_PAIRING_COMPLETE_RECEIPT: &str = "zinc-pairing-complete-receipt-v1";
const DOMAIN_SIGN_INTENT: &str = "zinc-sign-intent-v1";
const DOMAIN_SIGN_INTENT_RECEIPT: &str = "zinc-sign-intent-receipt-v1";

pub const NOSTR_SIGN_INTENT_APP_TAG_VALUE: &str = "zinc-sign-intent-v1";
pub const NOSTR_PAIRING_ACK_TYPE_TAG_VALUE: &str = "pairing-ack-v1";
pub const NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE: &str = "pairing-complete-receipt-v1";
pub const NOSTR_SIGN_INTENT_TYPE_TAG_VALUE: &str = "sign-intent-v1";
pub const NOSTR_SIGN_INTENT_RECEIPT_TYPE_TAG_VALUE: &str = "sign-intent-receipt-v1";
pub const PAIRING_TRANSPORT_EVENT_KIND: u64 = 1_059;
pub const NOSTR_TAG_APP_KEY: &str = "z";
pub const NOSTR_TAG_TYPE_KEY: &str = "t";
pub const NOSTR_TAG_PAIRING_HASH_KEY: &str = "x";
pub const NOSTR_TAG_RECIPIENT_PUBKEY_KEY: &str = "p";

const PAIRING_TRANSPORT_SEAL_EVENT_KIND: u64 = 13;
const PAIRING_TRANSPORT_RUMOR_EVENT_KIND: u64 = PAIRING_TRANSPORT_EVENT_KIND;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingAckEnvelopeV1 {
    pub version: u8,
    pub app_tag: String,
    pub type_tag: String,
    pub pairing_tag_hash_hex: String,
    pub created_at_unix: i64,
    pub signed_ack: SignedPairingAckV1,
}

impl PairingAckEnvelopeV1 {
    pub fn new(signed_ack: SignedPairingAckV1, created_at_unix: i64) -> Result<Self, ZincError> {
        signed_ack.verify()?;
        let pairing_tag_hash_hex = pairing_tag_hash_hex(&signed_ack.ack.pairing_id)?;
        let envelope = Self {
            version: VERSION_V1,
            app_tag: NOSTR_SIGN_INTENT_APP_TAG_VALUE.to_string(),
            type_tag: NOSTR_PAIRING_ACK_TYPE_TAG_VALUE.to_string(),
            pairing_tag_hash_hex,
            created_at_unix,
            signed_ack,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        if self.app_tag != NOSTR_SIGN_INTENT_APP_TAG_VALUE {
            return Err(ZincError::OfferError(format!(
                "pairing ack envelope app_tag must be `{NOSTR_SIGN_INTENT_APP_TAG_VALUE}`"
            )));
        }
        if self.type_tag != NOSTR_PAIRING_ACK_TYPE_TAG_VALUE {
            return Err(ZincError::OfferError(format!(
                "pairing ack envelope type_tag must be `{NOSTR_PAIRING_ACK_TYPE_TAG_VALUE}`"
            )));
        }
        validate_hex64(
            "pairing ack envelope pairing_tag_hash_hex",
            &self.pairing_tag_hash_hex,
        )?;
        self.signed_ack.verify()?;

        let expected_hash = pairing_tag_hash_hex(&self.signed_ack.ack.pairing_id)?;
        if self.pairing_tag_hash_hex != expected_hash {
            return Err(ZincError::OfferError(
                "pairing ack envelope pairing_tag_hash_hex does not match embedded pairing_id"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn envelope_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_PAIRING_ACK_ENVELOPE, &self.canonical_json()?)
    }

    pub fn envelope_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.envelope_id_digest()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NostrTransportEventV1 {
    pub id: String,
    pub pubkey: String,
    #[serde(rename = "created_at", alias = "createdAt")]
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrTransportEventV1 {
    pub fn new(
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
        created_at_unix: u64,
        secret_key_hex: &str,
    ) -> Result<Self, ZincError> {
        let secret_key = SecretKey::from_str(secret_key_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_hex = pubkey.to_string();

        let id = compute_nostr_event_id_hex(&pubkey_hex, created_at_unix, kind, &tags, &content)?;
        let sig = sign_nostr_event_id_hex(&id, &secret_key)?;

        let event = Self {
            id,
            pubkey: pubkey_hex,
            created_at: created_at_unix,
            kind,
            tags,
            content,
            sig,
        };
        event.verify()?;
        Ok(event)
    }

    pub fn verify(&self) -> Result<(), ZincError> {
        validate_hex64("nostr event id", &self.id)?;
        validate_pubkey_hex("nostr event pubkey", &self.pubkey)?;
        let expected_id = compute_nostr_event_id_hex(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if expected_id != self.id {
            return Err(ZincError::OfferError("nostr event id mismatch".to_string()));
        }

        let signature = Signature::from_str(&self.sig)
            .map_err(|e| ZincError::OfferError(format!("invalid nostr event signature: {e}")))?;
        let digest = hex_to_digest32(&self.id)?;
        let message = Message::from_digest(digest);
        let pubkey = XOnlyPublicKey::from_str(&self.pubkey)
            .map_err(|e| ZincError::OfferError(format!("invalid nostr event pubkey: {e}")))?;
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&signature, &message, &pubkey)
            .map_err(|e| {
                ZincError::OfferError(format!("nostr event signature verification failed: {e}"))
            })
    }

    pub fn tag_value(&self, key: &str) -> Option<&str> {
        self.tags.iter().find_map(|tag| {
            if tag.len() >= 2 && tag[0] == key {
                Some(tag[1].as_str())
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NostrTransportRumorV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    pubkey: String,
    #[serde(rename = "created_at", alias = "createdAt")]
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
}

impl NostrTransportRumorV1 {
    fn verify(&self) -> Result<(), ZincError> {
        validate_pubkey_hex("nostr rumor pubkey", &self.pubkey)?;
        if self.kind != PAIRING_TRANSPORT_RUMOR_EVENT_KIND {
            return Err(ZincError::OfferError(format!(
                "unexpected nostr rumor kind {}, expected {}",
                self.kind, PAIRING_TRANSPORT_RUMOR_EVENT_KIND
            )));
        }
        if let Some(id) = &self.id {
            validate_hex64("nostr rumor id", id)?;
            let expected_id = compute_nostr_event_id_hex(
                &self.pubkey,
                self.created_at,
                self.kind,
                &self.tags,
                &self.content,
            )?;
            if expected_id != *id {
                return Err(ZincError::OfferError("nostr rumor id mismatch".to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingCompleteReceiptStatusV1 {
    Confirmed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCompleteReceiptV1 {
    pub version: u8,
    pub pairing_id: String,
    pub ack_id: String,
    pub challenge_nonce: String,
    pub agent_pubkey_hex: String,
    pub wallet_pubkey_hex: String,
    pub created_at_unix: i64,
    pub status: PairingCompleteReceiptStatusV1,
    pub error_message: Option<String>,
}

impl PairingCompleteReceiptV1 {
    fn validate(&self) -> Result<(), ZincError> {
        validate_version(self.version)?;
        validate_hex64("pairing complete receipt pairing_id", &self.pairing_id)?;
        validate_hex64("pairing complete receipt ack_id", &self.ack_id)?;
        validate_nonce(
            "pairing complete receipt challenge_nonce",
            &self.challenge_nonce,
        )?;
        validate_pubkey_hex(
            "pairing complete receipt agent_pubkey_hex",
            &self.agent_pubkey_hex,
        )?;
        validate_pubkey_hex(
            "pairing complete receipt wallet_pubkey_hex",
            &self.wallet_pubkey_hex,
        )?;
        if let Some(message) = &self.error_message {
            ensure_non_empty("pairing complete receipt error_message", message)?;
        }

        match self.status {
            PairingCompleteReceiptStatusV1::Confirmed => {
                if self.error_message.is_some() {
                    return Err(ZincError::OfferError(
                        "confirmed pairing complete receipt must not include error_message"
                            .to_string(),
                    ));
                }
            }
            PairingCompleteReceiptStatusV1::Rejected => {
                if self.error_message.is_none() {
                    return Err(ZincError::OfferError(
                        "rejected pairing complete receipt must include error_message".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    pub fn receipt_id_digest(&self) -> Result<[u8; 32], ZincError> {
        domain_separated_digest(DOMAIN_PAIRING_COMPLETE_RECEIPT, &self.canonical_json()?)
    }

    pub fn receipt_id_hex(&self) -> Result<String, ZincError> {
        Ok(digest_hex(&self.receipt_id_digest()?))
    }

    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        sign_payload_with_expected_pubkey(
            secret_key_hex,
            &self.agent_pubkey_hex,
            DOMAIN_PAIRING_COMPLETE_RECEIPT,
            &self.canonical_json()?,
        )
    }

    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        verify_payload_signature(
            &self.agent_pubkey_hex,
            signature_hex,
            DOMAIN_PAIRING_COMPLETE_RECEIPT,
            &self.canonical_json()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPairingCompleteReceiptV1 {
    pub receipt: PairingCompleteReceiptV1,
    pub signature_hex: String,
}

impl SignedPairingCompleteReceiptV1 {
    pub fn new(receipt: PairingCompleteReceiptV1, secret_key_hex: &str) -> Result<Self, ZincError> {
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

pub fn build_signed_pairing_complete_receipt(
    signed_request: &SignedPairingRequestV1,
    signed_ack: &SignedPairingAckV1,
    agent_secret_key_hex: &str,
    now_unix: i64,
) -> Result<SignedPairingCompleteReceiptV1, ZincError> {
    let approval = verify_pairing_approval(signed_request, signed_ack, now_unix)?;
    let receipt = PairingCompleteReceiptV1 {
        version: VERSION_V1,
        pairing_id: approval.pairing_id,
        ack_id: signed_ack.ack_id_hex()?,
        challenge_nonce: signed_request.request.challenge_nonce.clone(),
        agent_pubkey_hex: approval.agent_pubkey_hex,
        wallet_pubkey_hex: approval.wallet_pubkey_hex,
        created_at_unix: now_unix,
        status: PairingCompleteReceiptStatusV1::Confirmed,
        error_message: None,
    };
    let signed = SignedPairingCompleteReceiptV1::new(receipt, agent_secret_key_hex)?;
    signed.verify()?;
    Ok(signed)
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
pub struct SignSellerInputScopeV1 {
    pub intent_id: String,
    pub offer_id: String,
    pub seller_input_index: usize,
    pub input_count: usize,
    pub expected_seller_outpoint: String,
    pub expected_ask_sats: u64,
}

pub fn verify_sign_seller_input_scope(
    signed_intent: &SignedSignIntentV1,
    now_unix: i64,
) -> Result<SignSellerInputScopeV1, ZincError> {
    signed_intent.verify()?;
    if now_unix > signed_intent.intent.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "sign seller input intent expired at {}",
            signed_intent.intent.expires_at_unix
        )));
    }

    let details = match &signed_intent.intent.payload {
        SignIntentPayloadV1::SignSellerInput(details) => details,
        _ => {
            return Err(ZincError::OfferError(
                "sign intent payload action must be SignSellerInput".to_string(),
            ))
        }
    };
    details.validate()?;

    let expected_seller_outpoint = details
        .expected_seller_outpoint
        .parse::<OutPoint>()
        .map_err(|e| {
            ZincError::OfferError(format!(
                "invalid sign seller input expected_seller_outpoint `{}`: {e}",
                details.expected_seller_outpoint
            ))
        })?;
    let psbt = decode_sign_seller_input_psbt(&details.offer_psbt_base64)?;
    let seller_input_index = locate_expected_seller_input(&psbt, expected_seller_outpoint)?;
    enforce_sign_seller_input_scope_constraints(
        &psbt,
        seller_input_index,
        expected_seller_outpoint,
        details.expected_ask_sats,
    )?;

    Ok(SignSellerInputScopeV1 {
        intent_id: signed_intent.intent_id_hex()?,
        offer_id: details.offer_id.clone(),
        seller_input_index,
        input_count: psbt.inputs.len(),
        expected_seller_outpoint: details.expected_seller_outpoint.clone(),
        expected_ask_sats: details.expected_ask_sats,
    })
}

pub fn verify_sign_seller_input_scope_json(
    signed_intent_json: &str,
    now_unix: i64,
) -> Result<SignSellerInputScopeV1, ZincError> {
    let signed_intent: SignedSignIntentV1 =
        serde_json::from_str(signed_intent_json).map_err(|e| {
            ZincError::SerializationError(format!("invalid signed sign intent json: {e}"))
        })?;
    verify_sign_seller_input_scope(&signed_intent, now_unix)
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

pub fn build_signed_sign_intent_rejection_receipt(
    signed_intent: &SignedSignIntentV1,
    wallet_secret_key_hex: &str,
    now_unix: i64,
    rejection_reason: &str,
) -> Result<SignedSignIntentReceiptV1, ZincError> {
    signed_intent.verify()?;
    ensure_non_empty("sign intent rejection reason", rejection_reason)?;
    let signer_pubkey_hex = pubkey_hex_from_secret_key(wallet_secret_key_hex)?;
    let receipt = SignIntentReceiptV1 {
        version: VERSION_V1,
        intent_id: signed_intent.intent_id_hex()?,
        pairing_id: signed_intent.intent.pairing_id.clone(),
        signer_pubkey_hex,
        created_at_unix: now_unix,
        status: SignIntentReceiptStatusV1::Rejected,
        signed_psbt_base64: None,
        artifact_json: None,
        error_message: Some(rejection_reason.to_string()),
    };
    let signed_receipt = SignedSignIntentReceiptV1::new(receipt, wallet_secret_key_hex)?;
    signed_receipt.verify()?;
    Ok(signed_receipt)
}

pub fn build_signed_sign_intent_approved_receipt(
    signed_intent: &SignedSignIntentV1,
    wallet_secret_key_hex: &str,
    now_unix: i64,
    signed_psbt_base64: Option<&str>,
    artifact_json: Option<&str>,
) -> Result<SignedSignIntentReceiptV1, ZincError> {
    signed_intent.verify()?;
    if now_unix > signed_intent.intent.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "sign intent expired at {}",
            signed_intent.intent.expires_at_unix
        )));
    }
    if signed_psbt_base64.is_none() && artifact_json.is_none() {
        return Err(ZincError::OfferError(
            "approved sign intent receipt must include signed_psbt_base64 or artifact_json"
                .to_string(),
        ));
    }

    if matches!(
        signed_intent.intent.payload,
        SignIntentPayloadV1::SignSellerInput(_)
    ) {
        verify_sign_seller_input_scope(signed_intent, now_unix)?;
        if signed_psbt_base64.is_none() {
            return Err(ZincError::OfferError(
                "approved SignSellerInput receipt must include signed_psbt_base64".to_string(),
            ));
        }
    }

    let signer_pubkey_hex = pubkey_hex_from_secret_key(wallet_secret_key_hex)?;
    let receipt = SignIntentReceiptV1 {
        version: VERSION_V1,
        intent_id: signed_intent.intent_id_hex()?,
        pairing_id: signed_intent.intent.pairing_id.clone(),
        signer_pubkey_hex,
        created_at_unix: now_unix,
        status: SignIntentReceiptStatusV1::Approved,
        signed_psbt_base64: signed_psbt_base64.map(str::to_string),
        artifact_json: artifact_json.map(str::to_string),
        error_message: None,
    };
    let signed_receipt = SignedSignIntentReceiptV1::new(receipt, wallet_secret_key_hex)?;
    signed_receipt.verify()?;
    Ok(signed_receipt)
}

fn decode_sign_seller_input_psbt(offer_psbt_base64: &str) -> Result<Psbt, ZincError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(offer_psbt_base64.as_bytes())
        .map_err(|e| {
            ZincError::OfferError(format!("invalid sign seller input psbt base64: {e}"))
        })?;
    Psbt::deserialize(&bytes)
        .map_err(|e| ZincError::OfferError(format!("invalid sign seller input psbt: {e}")))
}

fn locate_expected_seller_input(
    psbt: &Psbt,
    expected_seller_outpoint: OutPoint,
) -> Result<usize, ZincError> {
    let seller_indices: Vec<usize> = psbt
        .unsigned_tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            (input.previous_output == expected_seller_outpoint).then_some(index)
        })
        .collect();
    match seller_indices.len() {
        0 => Err(ZincError::OfferError(format!(
            "sign seller input psbt contains no expected seller input `{expected_seller_outpoint}`"
        ))),
        1 => Ok(seller_indices[0]),
        count => Err(ZincError::OfferError(format!(
            "sign seller input psbt contains {count} expected seller inputs `{expected_seller_outpoint}`"
        ))),
    }
}

fn enforce_sign_seller_input_scope_constraints(
    psbt: &Psbt,
    seller_input_index: usize,
    expected_seller_outpoint: OutPoint,
    expected_ask_sats: u64,
) -> Result<(), ZincError> {
    if seller_input_index != 0 {
        return Err(ZincError::OfferError(format!(
            "expected seller input `{expected_seller_outpoint}` must be first input (index 0), found index {seller_input_index}"
        )));
    }
    if psbt
        .inputs
        .get(seller_input_index)
        .is_some_and(psbt_input_has_signature)
    {
        return Err(ZincError::OfferError(format!(
            "expected seller input `{expected_seller_outpoint}` must be unsigned"
        )));
    }

    for (index, input) in psbt.inputs.iter().enumerate() {
        if index == seller_input_index {
            continue;
        }
        if !psbt_input_has_signature(input) {
            let outpoint = psbt.unsigned_tx.input[index].previous_output;
            return Err(ZincError::OfferError(format!(
                "buyer input `{outpoint}` must be signed before seller approval"
            )));
        }
    }

    let seller_postage_sats =
        seller_input_prevout_sats(psbt, seller_input_index, expected_seller_outpoint)?;
    if psbt.unsigned_tx.output.len() < 2 {
        return Err(ZincError::OfferError(
            "sign seller input psbt must include buyer postage and seller payout outputs"
                .to_string(),
        ));
    }

    let buyer_postage_out = &psbt.unsigned_tx.output[0];
    if buyer_postage_out.value.to_sat() != seller_postage_sats {
        return Err(ZincError::OfferError(format!(
            "expected buyer postage output at index 0 to equal seller postage {} sats; found {} sats",
            seller_postage_sats,
            buyer_postage_out.value.to_sat()
        )));
    }

    let expected_seller_payout = seller_postage_sats
        .checked_add(expected_ask_sats)
        .ok_or_else(|| {
            ZincError::OfferError(
                "sign seller input expected_ask_sats + postage overflows u64".to_string(),
            )
        })?;
    let seller_payout_out = &psbt.unsigned_tx.output[1];
    if seller_payout_out.value.to_sat() != expected_seller_payout {
        return Err(ZincError::OfferError(format!(
            "expected seller payout output at index 1 to equal ask+postage {} sats; found {} sats",
            expected_seller_payout,
            seller_payout_out.value.to_sat()
        )));
    }

    Ok(())
}

fn seller_input_prevout_sats(
    psbt: &Psbt,
    seller_input_index: usize,
    expected_seller_outpoint: OutPoint,
) -> Result<u64, ZincError> {
    let seller_input = psbt.inputs.get(seller_input_index).ok_or_else(|| {
        ZincError::OfferError("expected seller input metadata is missing".to_string())
    })?;
    let seller_txin = psbt
        .unsigned_tx
        .input
        .get(seller_input_index)
        .ok_or_else(|| ZincError::OfferError("expected seller tx input is missing".to_string()))?;

    seller_input
        .witness_utxo
        .as_ref()
        .map(|txout| txout.value.to_sat())
        .or_else(|| {
            seller_input.non_witness_utxo.as_ref().and_then(|prev_tx| {
                prev_tx
                    .output
                    .get(seller_txin.previous_output.vout as usize)
                    .map(|txout| txout.value.to_sat())
            })
        })
        .ok_or_else(|| {
            ZincError::OfferError(format!(
                "expected seller input `{expected_seller_outpoint}` is missing prevout value metadata"
            ))
        })
}

fn psbt_input_has_signature(input: &PsbtInput) -> bool {
    input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
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

pub fn validate_pairing_ack_envelope_json(payload_json: &str) -> Result<String, ZincError> {
    let envelope: PairingAckEnvelopeV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid pairing ack envelope json: {e}"))
    })?;
    envelope.validate()?;
    envelope.envelope_id_hex()
}

pub fn validate_signed_pairing_complete_receipt_json(
    payload_json: &str,
) -> Result<String, ZincError> {
    let signed: SignedPairingCompleteReceiptV1 =
        serde_json::from_str(payload_json).map_err(|e| {
            ZincError::SerializationError(format!(
                "invalid signed pairing complete receipt json: {e}"
            ))
        })?;
    signed.verify()?;
    signed.receipt_id_hex()
}

pub fn pairing_transport_tags(
    type_tag: &str,
    pairing_id: &str,
    recipient_pubkey_hex: &str,
) -> Result<Vec<Vec<String>>, ZincError> {
    if type_tag != NOSTR_PAIRING_ACK_TYPE_TAG_VALUE
        && type_tag != NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE
        && type_tag != NOSTR_SIGN_INTENT_TYPE_TAG_VALUE
        && type_tag != NOSTR_SIGN_INTENT_RECEIPT_TYPE_TAG_VALUE
    {
        return Err(ZincError::OfferError(format!(
            "unsupported pairing transport type tag `{type_tag}`"
        )));
    }
    validate_hex64("pairing id", pairing_id)?;
    validate_pubkey_hex("recipient pubkey", recipient_pubkey_hex)?;
    let pairing_hash = pairing_tag_hash_hex(pairing_id)?;
    Ok(vec![
        vec![
            NOSTR_TAG_APP_KEY.to_string(),
            NOSTR_SIGN_INTENT_APP_TAG_VALUE.to_string(),
        ],
        vec![NOSTR_TAG_TYPE_KEY.to_string(), type_tag.to_string()],
        vec![NOSTR_TAG_PAIRING_HASH_KEY.to_string(), pairing_hash],
        vec![
            NOSTR_TAG_RECIPIENT_PUBKEY_KEY.to_string(),
            recipient_pubkey_hex.to_string(),
        ],
    ])
}

pub fn build_pairing_transport_event(
    payload_json: &str,
    type_tag: &str,
    pairing_id: &str,
    recipient_pubkey_hex: &str,
    created_at_unix: u64,
    sender_secret_key_hex: &str,
) -> Result<NostrTransportEventV1, ZincError> {
    ensure_non_empty("pairing transport payload_json", payload_json)?;
    let tags = pairing_transport_tags(type_tag, pairing_id, recipient_pubkey_hex)?;
    let sender_pubkey_hex = pubkey_hex_from_secret_key(sender_secret_key_hex)?;

    let rumor = NostrTransportRumorV1 {
        id: None,
        pubkey: sender_pubkey_hex,
        created_at: created_at_unix,
        kind: PAIRING_TRANSPORT_RUMOR_EVENT_KIND,
        tags: tags.clone(),
        content: payload_json.to_string(),
    };
    rumor.verify()?;

    let rumor_json = serde_json::to_string(&rumor)
        .map_err(|e| ZincError::SerializationError(format!("failed to serialize rumor: {e}")))?;
    let seal_content = encrypt_pairing_transport_content(
        &rumor_json,
        sender_secret_key_hex,
        recipient_pubkey_hex,
    )?;
    let seal_event = NostrTransportEventV1::new(
        PAIRING_TRANSPORT_SEAL_EVENT_KIND,
        Vec::new(),
        seal_content,
        created_at_unix,
        sender_secret_key_hex,
    )?;

    let ephemeral_secret_key_hex = generate_secret_key_hex()?;
    let seal_event_json = serde_json::to_string(&seal_event).map_err(|e| {
        ZincError::SerializationError(format!("failed to serialize pairing transport seal: {e}"))
    })?;
    let wrapped_content = encrypt_pairing_transport_content(
        &seal_event_json,
        &ephemeral_secret_key_hex,
        recipient_pubkey_hex,
    )?;

    NostrTransportEventV1::new(
        PAIRING_TRANSPORT_EVENT_KIND,
        tags,
        wrapped_content,
        created_at_unix,
        &ephemeral_secret_key_hex,
    )
}

pub fn decode_pairing_transport_event_content_with_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<String, ZincError> {
    event.verify()?;
    ensure_supported_pairing_transport_event_kind(event.kind)?;
    ensure_event_recipient_tag_matches_secret(event, recipient_secret_key_hex)?;
    decrypt_pairing_transport_gift_wrap_content(event, recipient_secret_key_hex)
}

pub fn encrypt_pairing_transport_content(
    payload_json: &str,
    sender_secret_key_hex: &str,
    recipient_pubkey_hex: &str,
) -> Result<String, ZincError> {
    ensure_non_empty("pairing transport payload_json", payload_json)?;
    validate_pubkey_hex(
        "pairing transport recipient_pubkey_hex",
        recipient_pubkey_hex,
    )?;
    let sender_secret_key = parse_nostr_secret_key_hex(sender_secret_key_hex)?;
    let recipient_pubkey = parse_nostr_pubkey_hex(recipient_pubkey_hex)?;
    nip44::encrypt(
        &sender_secret_key,
        &recipient_pubkey,
        payload_json,
        nip44::Version::V2,
    )
    .map_err(|e| ZincError::OfferError(format!("failed to encrypt pairing transport payload: {e}")))
}

pub fn decrypt_pairing_transport_content(
    payload_ciphertext: &str,
    recipient_secret_key_hex: &str,
    sender_pubkey_hex: &str,
) -> Result<String, ZincError> {
    ensure_non_empty("pairing transport payload_ciphertext", payload_ciphertext)?;
    validate_pubkey_hex("pairing transport sender_pubkey_hex", sender_pubkey_hex)?;
    let recipient_secret_key = parse_nostr_secret_key_hex(recipient_secret_key_hex)?;
    let sender_pubkey = parse_nostr_pubkey_hex(sender_pubkey_hex)?;
    nip44::decrypt(&recipient_secret_key, &sender_pubkey, payload_ciphertext).map_err(|e| {
        ZincError::OfferError(format!("failed to decrypt pairing transport payload: {e}"))
    })
}

pub fn validate_nostr_transport_event_json(payload_json: &str) -> Result<String, ZincError> {
    let event: NostrTransportEventV1 = serde_json::from_str(payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid nostr transport event json: {e}"))
    })?;
    event.verify()?;
    Ok(event.id)
}

pub fn decode_pairing_ack_envelope_event(
    event: &NostrTransportEventV1,
) -> Result<PairingAckEnvelopeV1, ZincError> {
    decode_pairing_ack_envelope_event_internal(event, None)
}

pub fn decode_pairing_ack_envelope_event_with_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<PairingAckEnvelopeV1, ZincError> {
    decode_pairing_ack_envelope_event_internal(event, Some(recipient_secret_key_hex))
}

fn decode_pairing_ack_envelope_event_internal(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: Option<&str>,
) -> Result<PairingAckEnvelopeV1, ZincError> {
    event.verify()?;
    ensure_supported_pairing_transport_event_kind(event.kind)?;
    let payload_json = decode_pairing_transport_payload_json(
        event,
        NOSTR_PAIRING_ACK_TYPE_TAG_VALUE,
        recipient_secret_key_hex,
    )?;
    let envelope: PairingAckEnvelopeV1 = serde_json::from_str(&payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid pairing ack envelope json: {e}"))
    })?;
    envelope.validate()?;
    ensure_event_pairing_hash_matches(event, &envelope.signed_ack.ack.pairing_id)?;
    Ok(envelope)
}

pub fn decode_signed_pairing_complete_receipt_event(
    event: &NostrTransportEventV1,
) -> Result<SignedPairingCompleteReceiptV1, ZincError> {
    decode_signed_pairing_complete_receipt_event_internal(event, None)
}

pub fn decode_signed_pairing_complete_receipt_event_with_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<SignedPairingCompleteReceiptV1, ZincError> {
    decode_signed_pairing_complete_receipt_event_internal(event, Some(recipient_secret_key_hex))
}

fn decode_signed_pairing_complete_receipt_event_internal(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: Option<&str>,
) -> Result<SignedPairingCompleteReceiptV1, ZincError> {
    event.verify()?;
    ensure_supported_pairing_transport_event_kind(event.kind)?;
    let payload_json = decode_pairing_transport_payload_json(
        event,
        NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE,
        recipient_secret_key_hex,
    )?;
    let signed: SignedPairingCompleteReceiptV1 =
        serde_json::from_str(&payload_json).map_err(|e| {
            ZincError::SerializationError(format!(
                "invalid signed pairing complete receipt json: {e}"
            ))
        })?;
    signed.verify()?;
    ensure_event_pairing_hash_matches(event, &signed.receipt.pairing_id)?;
    Ok(signed)
}

pub fn decode_signed_sign_intent_event(
    event: &NostrTransportEventV1,
) -> Result<SignedSignIntentV1, ZincError> {
    decode_signed_sign_intent_event_internal(event, None)
}

pub fn decode_signed_sign_intent_event_with_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<SignedSignIntentV1, ZincError> {
    decode_signed_sign_intent_event_internal(event, Some(recipient_secret_key_hex))
}

fn decode_signed_sign_intent_event_internal(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: Option<&str>,
) -> Result<SignedSignIntentV1, ZincError> {
    event.verify()?;
    ensure_supported_pairing_transport_event_kind(event.kind)?;
    let payload_json = decode_pairing_transport_payload_json(
        event,
        NOSTR_SIGN_INTENT_TYPE_TAG_VALUE,
        recipient_secret_key_hex,
    )?;
    let signed: SignedSignIntentV1 = serde_json::from_str(&payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed sign intent json: {e}"))
    })?;
    signed.verify()?;
    ensure_event_pairing_hash_matches(event, &signed.intent.pairing_id)?;
    Ok(signed)
}

pub fn decode_signed_sign_intent_receipt_event(
    event: &NostrTransportEventV1,
) -> Result<SignedSignIntentReceiptV1, ZincError> {
    decode_signed_sign_intent_receipt_event_internal(event, None)
}

pub fn decode_signed_sign_intent_receipt_event_with_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<SignedSignIntentReceiptV1, ZincError> {
    decode_signed_sign_intent_receipt_event_internal(event, Some(recipient_secret_key_hex))
}

fn decode_signed_sign_intent_receipt_event_internal(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: Option<&str>,
) -> Result<SignedSignIntentReceiptV1, ZincError> {
    event.verify()?;
    ensure_supported_pairing_transport_event_kind(event.kind)?;
    let payload_json = decode_pairing_transport_payload_json(
        event,
        NOSTR_SIGN_INTENT_RECEIPT_TYPE_TAG_VALUE,
        recipient_secret_key_hex,
    )?;
    let signed: SignedSignIntentReceiptV1 = serde_json::from_str(&payload_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid signed sign intent receipt json: {e}"))
    })?;
    signed.verify()?;
    ensure_event_pairing_hash_matches(event, &signed.receipt.pairing_id)?;
    Ok(signed)
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

pub fn generate_secret_key_hex() -> Result<String, ZincError> {
    let mut candidate = [0u8; 32];
    loop {
        getrandom(&mut candidate)
            .map_err(|e| ZincError::OfferError(format!("failed to generate secret key: {e}")))?;
        if let Ok(secret_key) = SecretKey::from_slice(&candidate) {
            return Ok(bytes_to_hex_lower(&secret_key.secret_bytes()));
        }
    }
}

pub fn pairing_tag_hash_hex(pairing_id: &str) -> Result<String, ZincError> {
    validate_hex64("pairing id", pairing_id)?;
    let digest = domain_separated_digest(DOMAIN_PAIRING_TAG_HASH, pairing_id.as_bytes())?;
    Ok(digest_hex(&digest))
}

fn ensure_event_tags_match(
    event: &NostrTransportEventV1,
    expected_type_tag: &str,
) -> Result<(), ZincError> {
    let app_tag = event.tag_value(NOSTR_TAG_APP_KEY).ok_or_else(|| {
        ZincError::OfferError(format!(
            "nostr transport event missing `{NOSTR_TAG_APP_KEY}` tag"
        ))
    })?;
    if app_tag != NOSTR_SIGN_INTENT_APP_TAG_VALUE {
        return Err(ZincError::OfferError(format!(
            "nostr transport app tag must be `{NOSTR_SIGN_INTENT_APP_TAG_VALUE}`"
        )));
    }

    let type_tag = event.tag_value(NOSTR_TAG_TYPE_KEY).ok_or_else(|| {
        ZincError::OfferError(format!(
            "nostr transport event missing `{NOSTR_TAG_TYPE_KEY}` tag"
        ))
    })?;
    if type_tag != expected_type_tag {
        return Err(ZincError::OfferError(format!(
            "nostr transport type tag mismatch (expected `{expected_type_tag}`, got `{type_tag}`)"
        )));
    }

    let pairing_hash = event.tag_value(NOSTR_TAG_PAIRING_HASH_KEY).ok_or_else(|| {
        ZincError::OfferError(format!(
            "nostr transport event missing `{NOSTR_TAG_PAIRING_HASH_KEY}` tag"
        ))
    })?;
    validate_hex64("nostr transport pairing hash tag", pairing_hash)?;
    Ok(())
}

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn ensure_event_pairing_hash_matches(
    event: &NostrTransportEventV1,
    pairing_id: &str,
) -> Result<(), ZincError> {
    let expected = pairing_tag_hash_hex(pairing_id)?;
    let actual = event.tag_value(NOSTR_TAG_PAIRING_HASH_KEY).ok_or_else(|| {
        ZincError::OfferError(format!(
            "nostr transport event missing `{NOSTR_TAG_PAIRING_HASH_KEY}` tag"
        ))
    })?;
    if actual != expected {
        return Err(ZincError::OfferError(
            "nostr transport pairing hash tag does not match payload pairing id".to_string(),
        ));
    }
    Ok(())
}

fn ensure_supported_pairing_transport_event_kind(kind: u64) -> Result<(), ZincError> {
    if kind == PAIRING_TRANSPORT_EVENT_KIND {
        return Ok(());
    }
    Err(ZincError::OfferError(format!(
        "unexpected nostr event kind {}, expected {}",
        kind, PAIRING_TRANSPORT_EVENT_KIND
    )))
}

fn decrypt_pairing_transport_gift_wrap_content(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<String, ZincError> {
    let seal_json =
        decrypt_pairing_transport_content(&event.content, recipient_secret_key_hex, &event.pubkey)?;
    let seal_event: NostrTransportEventV1 = serde_json::from_str(&seal_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid pairing transport seal json: {e}"))
    })?;
    seal_event.verify()?;
    if seal_event.kind != PAIRING_TRANSPORT_SEAL_EVENT_KIND {
        return Err(ZincError::OfferError(format!(
            "unexpected pairing transport seal kind {}, expected {}",
            seal_event.kind, PAIRING_TRANSPORT_SEAL_EVENT_KIND
        )));
    }

    let rumor_json = decrypt_pairing_transport_content(
        &seal_event.content,
        recipient_secret_key_hex,
        &seal_event.pubkey,
    )?;
    let rumor: NostrTransportRumorV1 = serde_json::from_str(&rumor_json).map_err(|e| {
        ZincError::SerializationError(format!("invalid pairing transport rumor json: {e}"))
    })?;
    rumor.verify()?;
    if !rumor.pubkey.eq_ignore_ascii_case(&seal_event.pubkey) {
        return Err(ZincError::OfferError(
            "pairing transport rumor sender pubkey mismatch".to_string(),
        ));
    }
    Ok(rumor.content)
}

fn decode_pairing_transport_payload_json(
    event: &NostrTransportEventV1,
    expected_type_tag: &str,
    recipient_secret_key_hex: Option<&str>,
) -> Result<String, ZincError> {
    ensure_event_tags_match(event, expected_type_tag)?;
    if let Some(secret_key_hex) = recipient_secret_key_hex {
        return decode_pairing_transport_event_content_with_secret(event, secret_key_hex);
    }
    Ok(event.content.clone())
}

fn ensure_event_recipient_tag_matches_secret(
    event: &NostrTransportEventV1,
    recipient_secret_key_hex: &str,
) -> Result<(), ZincError> {
    let recipient_pubkey_hex = pubkey_hex_from_secret_key(recipient_secret_key_hex)?;
    let actual = event
        .tag_value(NOSTR_TAG_RECIPIENT_PUBKEY_KEY)
        .ok_or_else(|| {
            ZincError::OfferError(format!(
                "nostr transport event missing `{NOSTR_TAG_RECIPIENT_PUBKEY_KEY}` tag"
            ))
        })?;
    if actual != recipient_pubkey_hex {
        return Err(ZincError::OfferError(
            "nostr transport recipient pubkey tag does not match recipient secret key".to_string(),
        ));
    }
    Ok(())
}

fn parse_nostr_secret_key_hex(secret_key_hex: &str) -> Result<NostrSecretKey, ZincError> {
    NostrSecretKey::from_str(secret_key_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))
}

fn parse_nostr_pubkey_hex(pubkey_hex: &str) -> Result<NostrPublicKey, ZincError> {
    NostrPublicKey::from_hex(pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid pubkey hex: {e}")))
}

fn compute_nostr_event_id_hex(
    pubkey_hex: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<String, ZincError> {
    let payload = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    let serialized = serde_json::to_vec(&payload).map_err(|e| {
        ZincError::SerializationError(format!("failed to serialize nostr event payload: {e}"))
    })?;
    let digest = sha256::Hash::hash(&serialized);
    Ok(digest.to_string())
}

fn sign_nostr_event_id_hex(
    event_id_hex: &str,
    secret_key: &SecretKey,
) -> Result<String, ZincError> {
    let digest = hex_to_digest32(event_id_hex)?;
    let message = Message::from_digest(digest);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(signature.to_string())
}

fn hex_to_digest32(hex: &str) -> Result<[u8; 32], ZincError> {
    validate_hex64("digest", hex)?;
    let mut bytes = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk)
            .map_err(|e| ZincError::OfferError(format!("invalid digest hex utf8: {e}")))?;
        bytes[idx] = u8::from_str_radix(part, 16)
            .map_err(|e| ZincError::OfferError(format!("invalid digest hex byte: {e}")))?;
    }
    Ok(bytes)
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
