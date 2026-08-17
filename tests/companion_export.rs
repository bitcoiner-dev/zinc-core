use zinc_core::{
    AddressScheme, DerivationMode, LayoutSpec, PaymentAddressType, WalletBuilder, ZincMnemonic,
};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn mnemonic() -> ZincMnemonic {
    ZincMnemonic::parse(MNEMONIC).expect("BIP-39 vector")
}

#[test]
fn account_mode_recomputes_only_approved_public_material() {
    let wallet = WalletBuilder::from_mnemonic(bitcoin::Network::Regtest, &mnemonic())
        .with_scheme(AddressScheme::Dual)
        .with_payment_address_type(PaymentAddressType::NativeSegwit)
        .with_account_index(0)
        .build()
        .expect("seed wallet");

    let exported = wallet
        .companion_public_account_export(2)
        .expect("approved export");
    assert_eq!(exported.account_index(), 2);
    assert_eq!(exported.master_fingerprint(), &[0x73, 0xc5, 0xda, 0x0a]);
    assert!(exported
        .taproot_external_descriptor()
        .contains("[73c5da0a/86'/1'/2']"));
    assert!(exported.taproot_external_descriptor().contains("/0/*"));
    assert!(exported.taproot_internal_descriptor().contains("/1/*"));
    assert!(exported.payment_external_descriptor().starts_with("wpkh("));
    assert!(exported
        .payment_external_descriptor()
        .contains("[73c5da0a/84'/1'/2']"));
    assert!(exported.payment_external_descriptor().contains("/0/*"));
    assert_eq!(exported.verification_addresses().len(), 4);
    assert!(exported
        .verification_addresses()
        .iter()
        .all(|address| address.starts_with("bcrt1")));
}

#[test]
fn index_mode_fixes_both_formats_at_the_mobile_selected_logical_index() {
    let wallet = WalletBuilder::from_mnemonic(bitcoin::Network::Regtest, &mnemonic())
        .with_scheme(AddressScheme::Unified)
        .with_derivation_mode(DerivationMode::Index)
        .with_account_index(0)
        .build()
        .expect("seed wallet");

    let exported = wallet
        .companion_public_account_export(5)
        .expect("approved export");
    assert!(exported
        .taproot_external_descriptor()
        .contains("[73c5da0a/86'/1'/0']"));
    assert!(exported.taproot_external_descriptor().contains("/0/5"));
    assert!(!exported.taproot_external_descriptor().contains('*'));
    assert!(exported
        .payment_external_descriptor()
        .contains("[73c5da0a/84'/1'/0']"));
    assert!(exported.payment_external_descriptor().contains("/0/5"));
    assert!(!exported.payment_external_descriptor().contains('*'));
    assert_eq!(exported.verification_addresses().len(), 4);
}

#[test]
fn unsupported_layouts_and_watch_wallets_fail_closed() {
    let legacy_layout = LayoutSpec {
        payment: Some(zinc_core::BranchSpec {
            purpose: 49,
            script: zinc_core::ScriptKind::ShWpkh,
        }),
        ..LayoutSpec::zinc_default()
    };
    let wallet = WalletBuilder::from_mnemonic(bitcoin::Network::Regtest, &mnemonic())
        .with_layout(legacy_layout)
        .expect("representable legacy layout")
        .build()
        .expect("seed wallet");
    assert!(wallet.companion_public_account_export(0).is_err());

    let watched = WalletBuilder::from_watch_only(bitcoin::Network::Bitcoin)
        .with_xpub("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
        .expect("xpub")
        .build()
        .expect("watch wallet");
    assert!(watched.companion_public_account_export(0).is_err());
}
