//! Regression checks for plaintext secret ownership.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    decrypt_secret_with_key_internal, encrypt_secret_with_key_internal,
    generate_vault_key_internal, DecryptResponse, WalletMaterial, WalletResult,
};
use crate::{keys::ZincMnemonic, Network, WalletBuilder, WalletKind};
use bdk_wallet::KeychainKind;

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn mnemonic_result_owners_zeroize_automatically() {
    assert_zeroize_on_drop::<WalletResult>();
    assert_zeroize_on_drop::<DecryptResponse>();
}

#[test]
fn decrypted_secret_preserves_zeroizing_ownership() {
    let key = generate_vault_key_internal();
    let encrypted = encrypt_secret_with_key_internal("sensitive plaintext", &key).unwrap();
    let decrypted: Zeroizing<String> = decrypt_secret_with_key_internal(&encrypted, &key).unwrap();
    assert_eq!(decrypted.as_str(), "sensitive plaintext");
}

#[test]
fn stateful_wallet_material_zeroizes_automatically() {
    assert_zeroize_on_drop::<WalletMaterial>();
}

#[test]
#[allow(deprecated)]
fn locking_a_wallet_removes_live_signing_material() {
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = ZincMnemonic::parse(phrase).unwrap();
    let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic)
        .build()
        .unwrap();

    assert!(wallet.get_pairing_secret_key_hex().is_ok());
    assert!(!wallet
        .vault_wallet
        .get_signers(KeychainKind::External)
        .ids()
        .is_empty());
    wallet.lock_private_material();
    assert!(wallet.get_pairing_secret_key_hex().is_err());
    assert!(matches!(wallet.kind, WalletKind::WatchAddress(_)));
    assert!(wallet
        .vault_wallet
        .get_signers(KeychainKind::External)
        .ids()
        .is_empty());
    assert!(wallet
        .vault_wallet
        .get_signers(KeychainKind::Internal)
        .ids()
        .is_empty());
}
