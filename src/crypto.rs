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
    /// Version for future format changes.
    /// 1 = Argon2 64MB/3iter, 2 = Argon2 32MB/1iter (both password-derived),
    /// 3 = random 256-bit DEK held in the platform hardware keystore (NOT password-derived).
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

/// Encrypt a seed with a caller-supplied random 256-bit key (a "data encryption key")
/// used DIRECTLY as the AES-256-GCM key — no Argon2, no password stretching.
///
/// This is the version-3 vault: the key is high-entropy and lives in the platform hardware
/// keystore (iOS keychain/Secure Enclave, Android Keystore), released only after a device
/// user-presence check. Because the key is not derived from a PIN/password, a leaked vault
/// blob cannot be brute-forced offline — the entropy is in the key, not the user's secret.
/// The DEK is single-purpose, so it is used as the AES key with no further KDF.
pub fn encrypt_seed_with_key(seed: &[u8], key: &[u8; 32]) -> Result<EncryptedWallet, ZincError> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| ZincError::EncryptionError(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, seed)
        .map_err(|e| ZincError::EncryptionError(e.to_string()))?;

    Ok(EncryptedWallet {
        // Not password-derived, so there is no salt; kept empty for the shared struct shape.
        salt: String::new(),
        nonce: base64_encode(&nonce_bytes),
        ciphertext: base64_encode(&ciphertext),
        version: 3,
    })
}

/// Generate a fresh random 256-bit data encryption key for a version-3 vault.
///
/// The caller stores this in the platform hardware keystore; it is the only copy, so losing
/// the keystore entry means the vault can only be recovered by re-importing the mnemonic.
pub fn generate_vault_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Decrypt a version-3 vault with the 256-bit key retrieved from the hardware keystore.
pub fn decrypt_seed_with_key(
    encrypted: &EncryptedWallet,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ZincError> {
    if encrypted.version != 3 {
        return Err(ZincError::EncryptionError(format!(
            "decrypt_seed_with_key expects a version-3 (keystore-DEK) vault, got version {}",
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

/// Derive a 256-bit key from password using Argon2id.
fn derive_key(password: &str, salt: &str, version: u8) -> Result<Zeroizing<[u8; 32]>, ZincError> {
    let (m, t, p) = match version {
        1 => (V1_M_COST, V1_T_COST, V1_P_COST),
        2 => (V2_M_COST, V2_T_COST, V2_P_COST),
        _ => {
            return Err(ZincError::EncryptionError(format!(
                "Unsupported wallet version: {version}"
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

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let seed = b"another test seed value";
        let password = "pw";
        let mut encrypted = encrypt_seed(seed, password).unwrap();

        // Flip one byte of the ciphertext; AES-256-GCM authentication must reject it.
        let mut raw = base64_decode(&encrypted.ciphertext).unwrap();
        raw[0] ^= 0x01;
        encrypted.ciphertext = base64_encode(&raw);

        assert!(matches!(
            decrypt_seed(&encrypted, password),
            Err(ZincError::DecryptionError)
        ));
    }

    #[test]
    fn invalid_base64_ciphertext_is_reported_not_panicked() {
        let seed = b"seed";
        let password = "pw";
        let mut encrypted = encrypt_seed(seed, password).unwrap();
        encrypted.ciphertext = "!!! not base64 !!!".to_string();

        assert!(matches!(
            decrypt_seed(&encrypted, password),
            Err(ZincError::SerializationError(_))
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let seed = b"seed";
        let password = "pw";
        let mut encrypted = encrypt_seed(seed, password).unwrap();
        encrypted.version = 99;

        assert!(decrypt_seed(&encrypted, password).is_err());
    }

    #[test]
    fn derive_key_versions_differ_and_are_deterministic() {
        // `derive_key` consumes the salt as raw bytes; any >=8-byte string is valid.
        let salt = "saltsaltsalt1234";
        let k1a = derive_key("pw", salt, 1).unwrap();
        let k1b = derive_key("pw", salt, 1).unwrap();
        let k2 = derive_key("pw", salt, 2).unwrap();

        // Deterministic for a fixed (password, salt, version).
        assert_eq!(&*k1a, &*k1b);
        // Different Argon2 params (v1 = 64MB/3, v2 = 32MB/1) must yield different keys.
        assert_ne!(&*k1a, &*k2);
    }

    #[test]
    fn test_v3_dek_roundtrip() {
        let seed = b"this is a test seed for encryption";
        let key = [7u8; 32];

        let encrypted = encrypt_seed_with_key(seed, &key).unwrap();
        assert_eq!(encrypted.version, 3);
        assert!(encrypted.salt.is_empty(), "v3 is not password-derived, so carries no salt");

        let decrypted = decrypt_seed_with_key(&encrypted, &key).unwrap();
        assert_eq!(seed.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_generate_vault_key_is_fresh_each_call_and_round_trips() {
        let k1 = generate_vault_key();
        let k2 = generate_vault_key();
        assert_ne!(k1, k2, "each generated DEK must be independent");

        let seed = b"this is a test seed for encryption";
        let encrypted = encrypt_seed_with_key(seed, &k1).unwrap();
        let decrypted = decrypt_seed_with_key(&encrypted, &k1).unwrap();
        assert_eq!(seed.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v3_wrong_key_fails() {
        let encrypted = encrypt_seed_with_key(b"this is a test seed", &[7u8; 32]).unwrap();
        assert!(decrypt_seed_with_key(&encrypted, &[9u8; 32]).is_err());
    }

    #[test]
    fn test_v3_cannot_be_decrypted_by_the_password_path() {
        // A leaked v3 vault must not be offline-attackable via the password/Argon2 path —
        // there is no password to guess; the key lives in hardware. decrypt_seed refuses it.
        let encrypted = encrypt_seed_with_key(b"seed", &[7u8; 32]).unwrap();
        assert!(decrypt_seed(&encrypted, "any password whatsoever").is_err());
    }

    #[test]
    fn test_decrypt_with_key_rejects_a_password_derived_vault() {
        // Symmetrically, the keystore-DEK path must not accept a v1/v2 (password) vault.
        let encrypted = encrypt_seed(b"seed", "pw").unwrap(); // version 2
        assert!(decrypt_seed_with_key(&encrypted, &[7u8; 32]).is_err());
    }
}
