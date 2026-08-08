//! Tests for the version-3 (hardware-keystore DEK) vault seam exposed to the wallet.
//!
//! These exercise the JS-facing `*_internal` functions that the wasm bindings wrap, covering
//! the full mnemonic round-trip through a hex-encoded data encryption key, the hex-parsing
//! guards, and structural rejection of retired password-derived vaults.

use crate::{
    create_password_verifier_internal, crypto, decrypt_secret_with_key_internal,
    decrypt_wallet_with_key_internal, encrypt_secret_with_key_internal,
    encrypt_wallet_with_key_internal, generate_vault_key, generate_vault_key_internal,
    parse_vault_key_hex, verify_password_internal,
};
use zeroize::Zeroizing;

/// A valid 12-word BIP-39 mnemonic (the canonical all-`abandon` test vector).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn generate_vault_key_internal_is_64_hex_chars_and_fresh() {
    let k1: Zeroizing<String> = generate_vault_key_internal();
    let k2: Zeroizing<String> = generate_vault_key_internal();
    assert_eq!(k1.len(), 64, "32 bytes hex-encoded is 64 chars");
    assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(k1, k2, "each generated key must be independent");
}

#[test]
fn native_vault_key_export_preserves_zeroizing_ownership() {
    let key: Zeroizing<String> = generate_vault_key();
    assert_eq!(key.len(), 64);
}

#[test]
fn parsed_vault_key_is_zeroized_on_drop_without_an_intermediate_vec() {
    let parsed: Zeroizing<[u8; 32]> = parse_vault_key_hex(&"42".repeat(32)).unwrap();
    assert_eq!(&*parsed, &[0x42; 32]);
}

#[test]
fn v3_wallet_round_trips_through_the_hex_key() {
    let key_hex = generate_vault_key_internal();

    let vault = encrypt_wallet_with_key_internal(TEST_MNEMONIC, &key_hex).expect("encrypt v3");
    // The persisted blob must self-identify as version 3 so unlock routes to the keystore path.
    let parsed: crypto::EncryptedVault = serde_json::from_str(&vault).unwrap();
    assert_eq!(parsed.version, 3);

    let recovered = decrypt_wallet_with_key_internal(&vault, &key_hex).expect("decrypt v3");
    assert_eq!(recovered.phrase, TEST_MNEMONIC);
    assert_eq!(recovered.words.len(), 12);
}

#[test]
fn legacy_v3_wallet_with_empty_salt_unlocks_through_the_public_seam() {
    let key_hex = generate_vault_key_internal();
    let vault = encrypt_wallet_with_key_internal(TEST_MNEMONIC, &key_hex).expect("encrypt v3");
    let mut legacy: serde_json::Value = serde_json::from_str(&vault).expect("vault json");
    legacy
        .as_object_mut()
        .expect("vault object")
        .insert("salt".to_string(), serde_json::Value::String(String::new()));

    let recovered = decrypt_wallet_with_key_internal(&legacy.to_string(), &key_hex)
        .expect("legacy version-three vault should decrypt");
    assert_eq!(recovered.phrase, TEST_MNEMONIC);
}

#[test]
fn v3_decrypt_with_the_wrong_key_fails() {
    let vault =
        encrypt_wallet_with_key_internal(TEST_MNEMONIC, &generate_vault_key_internal()).unwrap();
    let other_key = generate_vault_key_internal();
    assert!(decrypt_wallet_with_key_internal(&vault, &other_key).is_err());
}

#[test]
fn malformed_vault_keys_are_rejected_not_panicked() {
    // Not hex.
    assert!(encrypt_wallet_with_key_internal(TEST_MNEMONIC, "not-hex!!").is_err());
    // Right alphabet, wrong length (31 bytes = 62 hex chars).
    let short = "ab".repeat(31);
    assert!(encrypt_wallet_with_key_internal(TEST_MNEMONIC, &short).is_err());
    // Too long (33 bytes).
    let long = "cd".repeat(33);
    assert!(encrypt_wallet_with_key_internal(TEST_MNEMONIC, &long).is_err());
}

#[test]
fn password_vault_shape_cannot_be_opened_by_the_keystore_path() {
    let v2_vault =
        r#"{"salt":"c2FsdA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA==","version":2}"#;
    let key_hex = generate_vault_key_internal();
    assert!(
        decrypt_wallet_with_key_internal(v2_vault, &key_hex).is_err(),
        "v3 path must refuse a version-2 vault"
    );
}

#[test]
fn v3_generic_secret_round_trips_through_the_hex_key() {
    let key_hex = generate_vault_key_internal();
    let vault = encrypt_secret_with_key_internal("private descriptor", &key_hex).unwrap();
    let recovered = decrypt_secret_with_key_internal(&vault, &key_hex).unwrap();
    assert_eq!(recovered.as_str(), "private descriptor");
}

#[test]
fn password_verifier_authenticates_without_encrypting_material() {
    let verifier = create_password_verifier_internal("correct horse").unwrap();
    assert!(verifier.starts_with("$argon2id$"));
    assert!(verify_password_internal(&verifier, "correct horse").unwrap());
    assert!(!verify_password_internal(&verifier, "wrong battery").unwrap());
}
