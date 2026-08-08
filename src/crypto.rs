//! Encryption module for wallet secret protection.
//!
//! Persisted secrets are encrypted with AES-256-GCM under a caller-supplied random data
//! encryption key (DEK). Password-derived encryption is intentionally unsupported.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use crate::error::ZincError;

/// A version-3 encrypted secret blob ready for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedVault {
    /// Older version-3 envelopes retained the password-vault `salt` field as an empty
    /// string. Accept that exact inert shape during reads, but never emit it again.
    #[serde(
        default,
        rename = "salt",
        skip_serializing,
        deserialize_with = "deserialize_legacy_empty_salt"
    )]
    _legacy_empty_salt: Option<()>,
    /// Nonce for AES-GCM (base64 encoded)
    pub nonce: String,
    /// Encrypted seed (base64 encoded)
    pub ciphertext: String,
    /// Format version. Version 3 uses a random 256-bit DEK held by the platform keystore.
    pub version: u8,
}

fn deserialize_legacy_empty_salt<'de, D>(deserializer: D) -> Result<Option<()>, D::Error>
where
    D: Deserializer<'de>,
{
    let salt = String::deserialize(deserializer)?;
    if salt.is_empty() {
        Ok(Some(()))
    } else {
        Err(de::Error::custom(
            "legacy version-3 salt must be an empty string",
        ))
    }
}

/// Encrypt a seed with a caller-supplied random 256-bit key (a "data encryption key")
/// used DIRECTLY as the AES-256-GCM key — no Argon2, no password stretching.
///
/// This is the version-3 vault: the key is high-entropy and lives in the platform hardware
/// keystore (iOS keychain/Secure Enclave, Android Keystore), released only after a device
/// user-presence check. Because the key is not derived from a PIN/password, a leaked vault
/// blob cannot be brute-forced offline — the entropy is in the key, not the user's secret.
/// The DEK is single-purpose, so it is used as the AES key with no further KDF.
pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedVault, ZincError> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| ZincError::EncryptionError(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    Ok(EncryptedVault {
        _legacy_empty_salt: None,
        nonce: base64_encode(&nonce_bytes),
        ciphertext: base64_encode(&ciphertext),
        version: 3,
    })
}

/// Generate a fresh random 256-bit data encryption key for a version-3 vault.
///
/// The caller stores this in the platform hardware keystore; it is the only copy, so losing
/// the keystore entry means the vault can only be recovered by re-importing the mnemonic.
pub fn generate_vault_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

/// Decrypt a version-3 vault with the 256-bit key retrieved from the hardware keystore.
pub fn decrypt_with_key(
    encrypted: &EncryptedVault,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ZincError> {
    if encrypted.version != 3 {
        return Err(ZincError::EncryptionError(format!(
            "decrypt_with_key expects a version-3 (keystore-DEK) vault, got version {}",
            encrypted.version
        )));
    }

    let nonce_bytes = base64_decode(&encrypted.nonce)?;
    let ciphertext = base64_decode(&encrypted.ciphertext)?;
    if nonce_bytes.len() != 12 {
        return Err(ZincError::DecryptionError);
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ZincError::DecryptionError)?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| ZincError::DecryptionError)?;

    Ok(Zeroizing::new(plaintext))
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, ZincError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(data)
        .map_err(|e| ZincError::SerializationError(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_vault_serialization() {
        let plaintext = b"test secret";
        let key = [7u8; 32];
        let encrypted = encrypt_with_key(plaintext, &key).unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        let parsed: EncryptedVault = serde_json::from_str(&json).unwrap();

        let decrypted = decrypt_with_key(&parsed, &key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        assert!(!json.contains("salt"));
    }

    #[test]
    fn test_malformed_nonce_length_fails_without_panic() {
        let mut encrypted = encrypt_with_key(b"test secret", &[7u8; 32]).unwrap();
        encrypted.nonce = base64_encode(&[0u8; 8]);

        let result = decrypt_with_key(&encrypted, &[7u8; 32]);
        assert!(matches!(result, Err(ZincError::DecryptionError)));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut encrypted = encrypt_with_key(b"another secret value", &[7u8; 32]).unwrap();

        // Flip one byte of the ciphertext; AES-256-GCM authentication must reject it.
        let mut raw = base64_decode(&encrypted.ciphertext).unwrap();
        raw[0] ^= 0x01;
        encrypted.ciphertext = base64_encode(&raw);

        assert!(matches!(
            decrypt_with_key(&encrypted, &[7u8; 32]),
            Err(ZincError::DecryptionError)
        ));
    }

    #[test]
    fn invalid_base64_ciphertext_is_reported_not_panicked() {
        let mut encrypted = encrypt_with_key(b"secret", &[7u8; 32]).unwrap();
        encrypted.ciphertext = "!!! not base64 !!!".to_string();

        assert!(matches!(
            decrypt_with_key(&encrypted, &[7u8; 32]),
            Err(ZincError::SerializationError(_))
        ));
    }

    #[test]
    fn non_v3_version_is_rejected() {
        let mut encrypted = encrypt_with_key(b"secret", &[7u8; 32]).unwrap();
        encrypted.version = 99;

        assert!(decrypt_with_key(&encrypted, &[7u8; 32]).is_err());
    }

    #[test]
    fn test_v3_dek_roundtrip() {
        let plaintext = b"this is a test secret";
        let key = [7u8; 32];

        let encrypted = encrypt_with_key(plaintext, &key).unwrap();
        assert_eq!(encrypted.version, 3);

        let decrypted = decrypt_with_key(&encrypted, &key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn legacy_v3_empty_salt_is_accepted_but_not_re_emitted() {
        let plaintext = b"legacy version-three secret";
        let key = [7u8; 32];
        let encrypted = encrypt_with_key(plaintext, &key).unwrap();
        let mut json = serde_json::to_value(&encrypted).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("salt".to_string(), serde_json::Value::String(String::new()));

        let parsed: EncryptedVault = serde_json::from_value(json).unwrap();
        let decrypted = decrypt_with_key(&parsed, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        assert!(!serde_json::to_string(&parsed).unwrap().contains("salt"));
    }

    #[test]
    fn non_empty_legacy_salt_is_rejected() {
        let encrypted = encrypt_with_key(b"secret", &[7u8; 32]).unwrap();
        let mut json = serde_json::to_value(&encrypted).unwrap();
        json.as_object_mut().unwrap().insert(
            "salt".to_string(),
            serde_json::Value::String("not-empty".to_string()),
        );

        assert!(serde_json::from_value::<EncryptedVault>(json).is_err());
    }

    #[test]
    fn test_generate_vault_key_is_fresh_each_call_and_round_trips() {
        let k1 = generate_vault_key();
        let k2 = generate_vault_key();
        assert_ne!(k1, k2, "each generated DEK must be independent");

        let plaintext = b"this is a test secret";
        let encrypted = encrypt_with_key(plaintext, &k1).unwrap();
        let decrypted = decrypt_with_key(&encrypted, &k1).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v3_wrong_key_fails() {
        let encrypted = encrypt_with_key(b"this is a test secret", &[7u8; 32]).unwrap();
        assert!(decrypt_with_key(&encrypted, &[9u8; 32]).is_err());
    }

    #[test]
    fn password_vault_shape_is_rejected() {
        let retired =
            r#"{"salt":"c2FsdA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA==","version":2}"#;
        assert!(serde_json::from_str::<EncryptedVault>(retired).is_err());
    }
}
