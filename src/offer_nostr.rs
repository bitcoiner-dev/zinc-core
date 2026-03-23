//! Nostr event primitives for decentralized offer publication and discovery.

use crate::{OfferEnvelopeV1, ZincError};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Nostr kind used for Zinc offer announcements.
pub const OFFER_EVENT_KIND: u64 = 8_756;
const OFFER_SCHEMA_TAG_VALUE: &str = "zinc-offer-v1";
const NIP40_EXPIRATION_TAG_KEY: &str = "expiration";
const LEGACY_EXPIRES_TAG_KEY: &str = "expires";

/// Nostr event carrying a canonical serialized [`OfferEnvelopeV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrOfferEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrOfferEvent {
    /// Create and sign a Nostr offer event from a canonical offer envelope.
    pub fn from_offer(
        offer: &OfferEnvelopeV1,
        secret_key_hex: &str,
        created_at_unix: u64,
    ) -> Result<Self, ZincError> {
        let secret_key = SecretKey::from_str(secret_key_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_hex = xonly_pubkey.to_string();

        if pubkey_hex != offer.seller_pubkey_hex {
            return Err(ZincError::OfferError(
                "secret key does not match offer seller_pubkey_hex".to_string(),
            ));
        }

        let content_bytes = offer.canonical_json()?;
        let content = String::from_utf8(content_bytes)
            .map_err(|e| ZincError::OfferError(format!("offer content is not utf8: {e}")))?;
        let offer_id = offer.offer_id_hex()?;

        let tags = vec![
            vec!["z".to_string(), OFFER_SCHEMA_TAG_VALUE.to_string()],
            vec!["network".to_string(), offer.network.clone()],
            vec!["inscription".to_string(), offer.inscription_id.clone()],
            vec!["offer_id".to_string(), offer_id],
            vec![
                NIP40_EXPIRATION_TAG_KEY.to_string(),
                offer.expires_at_unix.to_string(),
            ],
            vec![
                LEGACY_EXPIRES_TAG_KEY.to_string(),
                offer.expires_at_unix.to_string(),
            ],
        ];

        let id = compute_event_id_hex(
            &pubkey_hex,
            created_at_unix,
            OFFER_EVENT_KIND,
            &tags,
            &content,
        )?;
        let sig = sign_event_id_hex(&id, &secret_key)?;

        Ok(Self {
            id,
            pubkey: pubkey_hex,
            created_at: created_at_unix,
            kind: OFFER_EVENT_KIND,
            tags,
            content,
            sig,
        })
    }

    /// Verify event id integrity and Schnorr signature.
    pub fn verify(&self) -> Result<(), ZincError> {
        if !self.has_schema_tag() {
            return Err(ZincError::OfferError(
                "nostr offer event is missing schema tag".to_string(),
            ));
        }

        let expected_id = compute_event_id_hex(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if self.id != expected_id {
            return Err(ZincError::OfferError(
                "nostr offer event id mismatch".to_string(),
            ));
        }

        let pubkey = XOnlyPublicKey::from_str(&self.pubkey)
            .map_err(|e| ZincError::OfferError(format!("invalid event pubkey: {e}")))?;
        let signature = Signature::from_str(&self.sig)
            .map_err(|e| ZincError::OfferError(format!("invalid event signature: {e}")))?;
        let digest = hex_to_digest32(&self.id)?;
        let message = Message::from_digest(digest);

        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&signature, &message, &pubkey)
            .map_err(|e| ZincError::OfferError(format!("event signature verification failed: {e}")))
    }

    /// Decode and validate the embedded offer envelope payload.
    pub fn decode_offer(&self) -> Result<OfferEnvelopeV1, ZincError> {
        self.verify()?;
        let offer: OfferEnvelopeV1 = serde_json::from_str(&self.content)
            .map_err(|e| ZincError::OfferError(format!("invalid embedded offer json: {e}")))?;

        if offer.seller_pubkey_hex != self.pubkey {
            return Err(ZincError::OfferError(
                "event pubkey does not match embedded offer seller_pubkey_hex".to_string(),
            ));
        }

        if let Some(tag_offer_id) = self.tag_value("offer_id") {
            let embedded_offer_id = offer.offer_id_hex()?;
            if tag_offer_id != embedded_offer_id {
                return Err(ZincError::OfferError(
                    "embedded offer id does not match event offer_id tag".to_string(),
                ));
            }
        }

        validate_expiration_tag_matches_offer(self, &offer, NIP40_EXPIRATION_TAG_KEY)?;
        validate_expiration_tag_matches_offer(self, &offer, LEGACY_EXPIRES_TAG_KEY)?;

        Ok(offer)
    }

    /// Return first value for a `[key, value]` tag pair.
    pub fn tag_value(&self, key: &str) -> Option<&str> {
        self.tags.iter().find_map(|tag| {
            if tag.len() >= 2 && tag[0] == key {
                Some(tag[1].as_str())
            } else {
                None
            }
        })
    }

    fn has_schema_tag(&self) -> bool {
        self.tags
            .iter()
            .any(|tag| tag.len() >= 2 && tag[0] == "z" && tag[1] == OFFER_SCHEMA_TAG_VALUE)
    }
}

fn compute_event_id_hex(
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

fn sign_event_id_hex(event_id_hex: &str, secret_key: &SecretKey) -> Result<String, ZincError> {
    let digest = hex_to_digest32(event_id_hex)?;
    let message = Message::from_digest(digest);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(signature.to_string())
}

fn hex_to_digest32(hex: &str) -> Result<[u8; 32], ZincError> {
    if hex.len() != 64 {
        return Err(ZincError::OfferError(format!(
            "invalid digest hex length {}, expected 64",
            hex.len()
        )));
    }

    let mut bytes = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk)
            .map_err(|e| ZincError::OfferError(format!("invalid digest hex utf8: {e}")))?;
        bytes[idx] = u8::from_str_radix(part, 16)
            .map_err(|e| ZincError::OfferError(format!("invalid digest hex byte: {e}")))?;
    }
    Ok(bytes)
}

fn validate_expiration_tag_matches_offer(
    event: &NostrOfferEvent,
    offer: &OfferEnvelopeV1,
    tag_key: &str,
) -> Result<(), ZincError> {
    let Some(raw) = event.tag_value(tag_key) else {
        return Ok(());
    };
    let tag_unix = raw
        .parse::<i64>()
        .map_err(|e| ZincError::OfferError(format!("invalid {tag_key} tag value: {e}")))?;
    if tag_unix != offer.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "embedded offer expires_at_unix does not match event {tag_key} tag"
        )));
    }
    Ok(())
}
