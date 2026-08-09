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
    let old_signer_handle = wallet
        .vault_wallet
        .get_signers(KeychainKind::External)
        .clone();
    assert!(
        old_signer_handle.ids().is_empty(),
        "the persistent BDK wallet must be watch-only even while Zinc is unlocked"
    );
    assert!(wallet.sign_psbt("not-a-valid-psbt", None).is_err());
    wallet.lock_private_material();
    assert!(wallet.get_pairing_secret_key_hex().is_err());
    assert!(matches!(wallet.kind, WalletKind::WatchAddress(_)));
    let after_lock = wallet
        .sign_psbt("not-a-valid-psbt", None)
        .expect_err("a locked wallet must reject signing before parsing the PSBT");
    assert!(after_lock.contains("Capability missing"));
    assert!(
        old_signer_handle.ids().is_empty(),
        "an old BDK signer handle must not retain signing capability after lock"
    );
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

#[test]
fn dual_seed_wallet_retains_only_public_descriptors_and_empty_signers() {
    let wallet = WalletBuilder::from_seed(
        Network::Regtest,
        crate::builder::Seed64::from_array([7; 64]),
    )
    .with_scheme(crate::builder::AddressScheme::Dual)
    .build()
    .expect("dual seed wallet");

    for bdk_wallet in [
        &wallet.vault_wallet,
        wallet
            .payment_wallet
            .as_ref()
            .expect("dual wallet should include payment wallet"),
    ] {
        assert!(
            bdk_wallet
                .get_signers(KeychainKind::External)
                .ids()
                .is_empty(),
            "external persistent signer map must be empty"
        );
        assert!(
            bdk_wallet
                .get_signers(KeychainKind::Internal)
                .ids()
                .is_empty(),
            "internal persistent signer map must be empty"
        );
    }

    let persistence = wallet.export_changeset().expect("persistence");
    let taproot = persistence
        .taproot
        .expect("dual persistence should include taproot changeset");
    let payment = persistence
        .payment
        .expect("dual persistence should include payment changeset");
    for descriptor in [
        taproot.descriptor,
        taproot.change_descriptor,
        payment.descriptor,
        payment.change_descriptor,
    ]
    .into_iter()
    .flatten()
    {
        let rendered = descriptor.to_string();
        assert!(
            !rendered.contains("prv"),
            "private descriptor was persisted"
        );
        rendered
            .parse::<bdk_wallet::descriptor::Descriptor<
                bdk_wallet::descriptor::DescriptorPublicKey,
            >>()
            .expect("persisted payment descriptor must contain public keys only");
    }
}
