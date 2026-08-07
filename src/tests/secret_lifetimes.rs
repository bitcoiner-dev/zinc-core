//! Regression checks for plaintext secret ownership.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    decrypt_secret_internal, encrypt_secret_internal, DecryptResponse, WalletMaterial, WalletResult,
};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn mnemonic_result_owners_zeroize_automatically() {
    assert_zeroize_on_drop::<WalletResult>();
    assert_zeroize_on_drop::<DecryptResponse>();
}

#[test]
fn decrypted_secret_preserves_zeroizing_ownership() {
    let encrypted = encrypt_secret_internal("sensitive plaintext", "password").unwrap();
    let decrypted: Zeroizing<String> = decrypt_secret_internal(&encrypted, "password").unwrap();
    assert_eq!(decrypted.as_str(), "sensitive plaintext");
}

#[test]
fn stateful_wallet_material_zeroizes_automatically() {
    assert_zeroize_on_drop::<WalletMaterial>();
}
