#![allow(clippy::expect_used)]
use zinc_core::*;

#[test]
fn test_full_creation_flow() {
    // 1. Generate Wallet (Simulate "Create New Wallet")
    let wallet_res = generate_wallet_internal(12).expect("Generation failed");

    let phrase = &wallet_res.phrase;
    let words = &wallet_res.words;

    assert_eq!(words.len(), 12);
    assert!(!phrase.is_empty());

    // 2. Encrypt Wallet (Simulate "Set Password")
    let password = "super_secure_password";
    let encrypted_blob = encrypt_wallet_internal(phrase, password).expect("Encryption failed");

    // 3. Decrypt Wallet (Simulate "Unlock")
    let decrypted_res =
        decrypt_wallet_internal(&encrypted_blob, password).expect("Decryption failed");

    // 4. Verify Identity
    assert_eq!(&decrypted_res.phrase, phrase);
    assert_eq!(&decrypted_res.words, words);
}

#[test]
fn test_full_restore_flow() {
    // 1. User inputs phrase (Simulate "Restore Wallet")
    let original_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 2. Validate input
    assert!(validate_mnemonic_internal(original_phrase));

    // 3. Encrypt (Simulate "Set Password")
    let password = "restore_password_123";
    let encrypted_blob =
        encrypt_wallet_internal(original_phrase, password).expect("Encryption failed");

    // 4. Decrypt (Simulate "Unlock" to use)
    let decrypted_res =
        decrypt_wallet_internal(&encrypted_blob, password).expect("Decryption failed");

    // 5. Verify restored matches original
    assert_eq!(decrypted_res.phrase, original_phrase);
}
