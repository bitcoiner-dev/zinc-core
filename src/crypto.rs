//! Encryption module for wallet seed protection
//!
//! Uses Argon2id for key derivation and AES-256-GCM for encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, Params};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::ZincError;

/// Argon2 parameters for key derivation.
/// Version 1: 64MB memory, 3 iterations - secure but slow for browser.
const V1_M_COST: u32 = 65536; // 64 MB
const V1_T_COST: u32 = 3;
const V1_P_COST: u32 = 1;

/// Version 2: 32MB memory, 1 iteration - ~3x faster, balanced for UX.
const V2_M_COST: u32 = 32768; // 32 MB
const V2_T_COST: u32 = 1;
const V2_P_COST: u32 = 1;

/// An encrypted wallet blob ready for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Salt for Argon2 (base64 encoded)
    pub salt: String,
    /// Nonce for AES-GCM (base64 encoded)
    pub nonce: String,
    /// Encrypted seed (base64 encoded)
    pub ciphertext: String,
    /// Version for future format changes
    /// 1 = 64MB/3 iter, 2 = 32MB/1 iter
    pub version: u8,
}

/// Encrypt a seed with a password using Argon2id + AES-256-GCM.
pub fn encrypt_seed(seed: &[u8], password: &str) -> Result<EncryptedWallet, ZincError> {
    // Generate random salt
    let salt = SaltString::generate(&mut OsRng);

    // Default to newest version (v2) for new encryptions
    let version = 2;

    // Derive key using Argon2id
    let key = derive_key(password, salt.as_str(), version)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, seed)
        .map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    Ok(EncryptedWallet {
        salt: salt.to_string(),
        nonce: base64_encode(&nonce_bytes),
        ciphertext: base64_encode(&ciphertext),
        version,
    })
}

/// Decrypt an encrypted wallet with a password.
pub fn decrypt_seed(
    encrypted: &EncryptedWallet,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, ZincError> {
    // Derive key using Argon2id with version-specific parameters
    let key = derive_key(password, &encrypted.salt, encrypted.version)?;

    // Decode nonce and ciphertext
    let nonce_bytes = base64_decode(&encrypted.nonce)?;
    let ciphertext = base64_decode(&encrypted.ciphertext)?;

    // `Nonce::from_slice` panics when length != 12. Treat malformed payloads as decryption failure.
    if nonce_bytes.len() != 12 {
        return Err(ZincError::DecryptionError);
    }

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| ZincError::DecryptionError)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| ZincError::DecryptionError)?;

    Ok(Zeroizing::new(plaintext))
}

/// Derive a 256-bit key from password using Argon2id.
fn derive_key(password: &str, salt: &str, version: u8) -> Result<Zeroizing<[u8; 32]>, ZincError> {
    let (m, t, p) = match version {
        1 => (V1_M_COST, V1_T_COST, V1_P_COST),
        2 => (V2_M_COST, V2_T_COST, V2_P_COST),
        _ => {
            return Err(ZincError::EncryptionError(format!(
                "Unsupported wallet version: {}",
                version
            )))
        }
    };

    let params =
        Params::new(m, t, p, Some(32)).map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut *key)
        .map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    Ok(key)
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
    fn test_encrypt_decrypt_roundtrip() {
        let seed = b"this is a test seed for encryption";
        let password = "secure_password_123!";

        let encrypted = encrypt_seed(seed, password).unwrap();
        let decrypted = decrypt_seed(&encrypted, password).unwrap();

        assert_eq!(seed.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let seed = b"this is a test seed for encryption";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt_seed(seed, password).unwrap();
        let result = decrypt_seed(&encrypted, wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_wallet_serialization() {
        let seed = b"test seed";
        let password = "password";

        let encrypted = encrypt_seed(seed, password).unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        let parsed: EncryptedWallet = serde_json::from_str(&json).unwrap();

        let decrypted = decrypt_seed(&parsed, password).unwrap();
        assert_eq!(seed.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_malformed_nonce_length_fails_without_panic() {
        let seed = b"test seed";
        let password = "password";

        let mut encrypted = encrypt_seed(seed, password).unwrap();
        encrypted.nonce = base64_encode(&[0u8; 8]);

        let result = decrypt_seed(&encrypted, password);
        assert!(matches!(result, Err(ZincError::DecryptionError)));
    }
}
