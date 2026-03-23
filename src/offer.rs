//! Offer envelope primitives for decentralized offer publishing and discovery.
//!
//! This module provides deterministic serialization, stable offer hashing,
//! and Schnorr signature/verification helpers for offer payloads.

use crate::ZincError;
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Canonical offer envelope v1.
///
/// Field order is intentionally fixed and used as canonical serialization order
/// for offer hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferEnvelopeV1 {
    /// Envelope schema version.
    pub version: u8,
    /// Seller identity key as x-only secp256k1 public key hex.
    pub seller_pubkey_hex: String,
    /// Bitcoin network identifier.
    pub network: String,
    /// Inscription identifier.
    pub inscription_id: String,
    /// Outpoint containing the offered inscription (`txid:vout`).
    pub seller_outpoint: String,
    /// Ask price in satoshis.
    pub ask_sats: u64,
    /// Fee rate target in sat/vB for finalized transaction.
    pub fee_rate_sat_vb: u64,
    /// Seller offer PSBT (base64).
    pub psbt_base64: String,
    /// UNIX timestamp (seconds) offer creation time.
    pub created_at_unix: i64,
    /// UNIX timestamp (seconds) offer expiration time.
    pub expires_at_unix: i64,
    /// Caller-controlled nonce for replay-resistant uniqueness.
    pub nonce: u64,
}

impl OfferEnvelopeV1 {
    fn validate(&self) -> Result<(), ZincError> {
        if self.version != 1 {
            return Err(ZincError::OfferError(format!(
                "unsupported offer version {}",
                self.version
            )));
        }

        if self.seller_pubkey_hex.is_empty()
            || self.network.is_empty()
            || self.inscription_id.is_empty()
            || self.seller_outpoint.is_empty()
            || self.psbt_base64.is_empty()
        {
            return Err(ZincError::OfferError(
                "offer contains empty required fields".to_string(),
            ));
        }

        if self.expires_at_unix <= self.created_at_unix {
            return Err(ZincError::OfferError(
                "offer expiration must be greater than creation time".to_string(),
            ));
        }

        Ok(())
    }

    /// Serialize this envelope using canonical JSON bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    /// Compute the SHA-256 offer id digest bytes.
    pub fn offer_id_digest(&self) -> Result<[u8; 32], ZincError> {
        let canonical = self.canonical_json()?;
        let digest = sha256::Hash::hash(&canonical);
        Ok(digest.to_byte_array())
    }

    /// Compute the SHA-256 offer id hex string.
    pub fn offer_id_hex(&self) -> Result<String, ZincError> {
        let digest = self.offer_id_digest()?;
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Sign the offer id digest with a Schnorr key (hex-encoded secret key).
    pub fn sign_schnorr_hex(&self, secret_key_hex: &str) -> Result<String, ZincError> {
        let secret_key = SecretKey::from_str(secret_key_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid secret key: {e}")))?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let message = Message::from_digest(self.offer_id_digest()?);
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        Ok(signature.to_string())
    }

    /// Verify a Schnorr signature (hex) against `seller_pubkey_hex`.
    pub fn verify_schnorr_hex(&self, signature_hex: &str) -> Result<(), ZincError> {
        let pubkey = XOnlyPublicKey::from_str(&self.seller_pubkey_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid seller pubkey: {e}")))?;
        let signature = Signature::from_str(signature_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid schnorr signature: {e}")))?;

        let secp = Secp256k1::verification_only();
        let message = Message::from_digest(self.offer_id_digest()?);

        secp.verify_schnorr(&signature, &message, &pubkey)
            .map_err(|e| ZincError::OfferError(format!("signature verification failed: {e}")))
    }
}
