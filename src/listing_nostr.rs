//! Nostr event primitives for decentralized fixed-price listing publication and discovery.

use crate::{ListingEnvelopeV1, ZincError};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Nostr kind used for Zinc fixed-price listing announcements.
pub const LISTING_EVENT_KIND: u64 = 8_757;
pub(crate) const LISTING_SCHEMA_TAG_VALUE: &str = "zinc-listing-v1";
const NIP40_EXPIRATION_TAG_KEY: &str = "expiration";
const LEGACY_EXPIRES_TAG_KEY: &str = "expires";

/// Nostr event carrying a canonical serialized [`ListingEnvelopeV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrListingEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrListingEvent {
    /// Create and sign a Nostr listing event from a canonical listing envelope.
    pub fn from_listing(
        listing: &ListingEnvelopeV1,
        secret_key_hex: &str,
        created_at_unix: u64,
    ) -> Result<Self, ZincError> {
        let secret_key = SecretKey::from_str(secret_key_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_hex = xonly_pubkey.to_string();

        if pubkey_hex != listing.seller_pubkey_hex {
            return Err(ZincError::OfferError(
                "secret key does not match listing seller_pubkey_hex".to_string(),
            ));
        }

        let content_bytes = listing.canonical_json()?;
        let content = String::from_utf8(content_bytes)
            .map_err(|e| ZincError::OfferError(format!("listing content is not utf8: {e}")))?;
        let listing_id = listing.listing_id_hex()?;

        let tags = vec![
            vec!["z".to_string(), LISTING_SCHEMA_TAG_VALUE.to_string()],
            vec!["network".to_string(), listing.network.clone()],
            vec!["inscription".to_string(), listing.inscription_id.clone()],
            vec!["listing_id".to_string(), listing_id],
            vec![
                NIP40_EXPIRATION_TAG_KEY.to_string(),
                listing.expires_at_unix.to_string(),
            ],
            vec![
                LEGACY_EXPIRES_TAG_KEY.to_string(),
                listing.expires_at_unix.to_string(),
            ],
        ];

        let id = compute_event_id_hex(
            &pubkey_hex,
            created_at_unix,
            LISTING_EVENT_KIND,
            &tags,
            &content,
        )?;
        let sig = sign_event_id_hex(&id, &secret_key)?;

        Ok(Self {
            id,
            pubkey: pubkey_hex,
            created_at: created_at_unix,
            kind: LISTING_EVENT_KIND,
            tags,
            content,
            sig,
        })
    }

    /// Verify event id integrity and Schnorr signature.
    pub fn verify(&self) -> Result<(), ZincError> {
        if !self.has_schema_tag() {
            return Err(ZincError::OfferError(
                "nostr listing event is missing schema tag".to_string(),
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
                "nostr listing event id mismatch".to_string(),
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

    /// Decode and validate the embedded listing envelope payload.
    pub fn decode_listing(&self) -> Result<ListingEnvelopeV1, ZincError> {
        self.verify()?;
        let listing: ListingEnvelopeV1 = serde_json::from_str(&self.content)
            .map_err(|e| ZincError::OfferError(format!("invalid embedded listing json: {e}")))?;

        if listing.seller_pubkey_hex != self.pubkey {
            return Err(ZincError::OfferError(
                "event pubkey does not match embedded listing seller_pubkey_hex".to_string(),
            ));
        }

        if let Some(tag_listing_id) = self.tag_value("listing_id") {
            let embedded_listing_id = listing.listing_id_hex()?;
            if tag_listing_id != embedded_listing_id {
                return Err(ZincError::OfferError(
                    "embedded listing id does not match event listing_id tag".to_string(),
                ));
            }
        }

        validate_expiration_tag_matches_listing(self, &listing, NIP40_EXPIRATION_TAG_KEY)?;
        validate_expiration_tag_matches_listing(self, &listing, LEGACY_EXPIRES_TAG_KEY)?;

        Ok(listing)
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
            .any(|tag| tag.len() >= 2 && tag[0] == "z" && tag[1] == LISTING_SCHEMA_TAG_VALUE)
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

fn validate_expiration_tag_matches_listing(
    event: &NostrListingEvent,
    listing: &ListingEnvelopeV1,
    tag_key: &str,
) -> Result<(), ZincError> {
    let Some(raw) = event.tag_value(tag_key) else {
        return Ok(());
    };
    let tag_unix = raw
        .parse::<i64>()
        .map_err(|e| ZincError::OfferError(format!("invalid {tag_key} tag value: {e}")))?;
    if tag_unix != listing.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "embedded listing expires_at_unix does not match event {tag_key} tag"
        )));
    }
    Ok(())
}
