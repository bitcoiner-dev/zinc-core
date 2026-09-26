//! Ownership lookup must stay fast without losing multi-address/import compatibility.
use super::*;
use base64::Engine;
use bitcoin::secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};

fn wallet(mode: DerivationMode, account: u32, payment: PaymentAddressType) -> ZincWallet {
    WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
        .with_scheme(AddressScheme::Dual)
        .with_derivation_mode(mode)
        .with_account_index(account)
        .with_payment_address_type(payment)
        .build()
        .unwrap()
}

fn branch(wallet: &ZincWallet, payment: bool) -> &Wallet {
    if payment {
        wallet.payment_wallet.as_ref().unwrap()
    } else {
        &wallet.vault_wallet
    }
}

fn reveal(wallet: &mut ZincWallet, payment: bool, chain: KeychainKind, index: u32) -> Address {
    let branch = if payment {
        wallet.payment_wallet.as_mut().unwrap()
    } else {
        &mut wallet.vault_wallet
    };
    branch.reveal_addresses_to(chain, index).for_each(drop);
    branch.peek_address(chain, index).address
}

fn indexed(wallet: &ZincWallet, address: &Address) -> OwnedAddressMatch {
    wallet
        .find_owned_address_with_fallback(&address.to_string(), |_, _, _| {
            panic!("indexed address must not enter the derivation scan")
        })
        .expect("owned address")
}

fn assert_match(found: OwnedAddressMatch, purpose: u32, chain: KeychainKind, index: u32) {
    assert_eq!(found.purpose, purpose);
    assert_eq!(found.keychain, chain);
    assert_eq!(found.absolute_index, index);
}

fn verify_signature(
    wallet: &ZincWallet,
    address: &Address,
    purpose: u32,
    chain: KeychainKind,
    index: u32,
) {
    let message = "synthetic ownership regression test";
    let signature = wallet.sign_message(&address.to_string(), message).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .unwrap();
    let signature = RecoverableSignature::from_compact(
        &bytes[1..],
        RecoveryId::from_i32(i32::from(bytes[0] - 31)).unwrap(),
    )
    .unwrap();
    let hash = bitcoin::sign_message::signed_msg_hash(message);
    let secp = Secp256k1::new();
    let public_key = secp
        .recover_ecdsa(&Message::from_digest(hash.to_byte_array()), &signature)
        .unwrap();
    let key = wallet
        .derive_private_key_internal(
            purpose,
            wallet.active_derivation_account(),
            if chain == KeychainKind::External {
                0
            } else {
                1
            },
            index,
        )
        .unwrap();
    assert_eq!(
        public_key,
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key)
    );
}

#[test]
fn indexed_receive_and_change_sign_without_scanning_in_both_account_modes() {
    for mode in [DerivationMode::Account, DerivationMode::Index] {
        let mut wallet = wallet(mode, 7, PaymentAddressType::NativeSegwit);
        for payment in [false, true] {
            let purpose = if payment { 84 } else { 86 };
            for chain in [KeychainKind::External, KeychainKind::Internal] {
                for index in [0, 7, 37] {
                    let address = reveal(&mut wallet, payment, chain, index);
                    let key_index = if mode == DerivationMode::Index {
                        7
                    } else {
                        index
                    };
                    assert_match(indexed(&wallet, &address), purpose, chain, key_index);
                    verify_signature(&wallet, &address, purpose, chain, key_index);
                }
            }
        }
    }
}

#[test]
fn all_supported_payment_scripts_use_the_index() {
    for kind in [
        PaymentAddressType::NativeSegwit,
        PaymentAddressType::NestedSegwit,
        PaymentAddressType::Legacy,
    ] {
        let mut wallet = wallet(DerivationMode::Account, 2, kind);
        let address = reveal(&mut wallet, true, KeychainKind::Internal, 37);
        assert_match(
            indexed(&wallet, &address),
            kind.purpose(),
            KeychainKind::Internal,
            37,
        );
        verify_signature(
            &wallet,
            &address,
            kind.purpose(),
            KeychainKind::Internal,
            37,
        );
    }
}

#[test]
fn primary_payment_address_never_scans_taproot() {
    let wallet = wallet(DerivationMode::Account, 0, PaymentAddressType::NativeSegwit);
    assert_match(
        indexed(&wallet, &wallet.peek_payment_address(0).unwrap()),
        84,
        KeychainKind::External,
        0,
    );
}

#[test]
fn unindexed_receive_and_change_keep_the_compatibility_search() {
    for mode in [DerivationMode::Account] {
        let wallet = wallet(mode, 7, PaymentAddressType::NativeSegwit);
        for payment in [false, true] {
            let purpose = if payment { 84 } else { 86 };
            for chain in [KeychainKind::External, KeychainKind::Internal] {
                let address = branch(&wallet, payment).peek_address(chain, 80).address;
                assert!(branch(&wallet, payment)
                    .derivation_of_spk(address.script_pubkey())
                    .is_none());
                let mut scans = 0;
                let found = wallet
                    .find_owned_address_with_fallback(
                        &address.to_string(),
                        |candidate, script, selected_purpose| {
                            scans += 1;
                            assert_eq!(selected_purpose, purpose);
                            assert!(std::ptr::eq(candidate, branch(&wallet, payment)));
                            wallet.scan_owned_address_in_wallet(
                                candidate,
                                script,
                                selected_purpose,
                                100,
                            )
                        },
                    )
                    .unwrap();
                assert_eq!(scans, 1);
                assert_match(found, purpose, chain, 80);
                verify_signature(&wallet, &address, purpose, chain, 80);
            }
        }
    }
}

#[test]
fn index_mode_rejects_sibling_receive_and_change_keys() {
    let selected = wallet(
        DerivationMode::Index,
        1500,
        PaymentAddressType::NativeSegwit,
    );
    let siblings = wallet(DerivationMode::Account, 0, PaymentAddressType::NativeSegwit);
    for payment in [false, true] {
        for chain in [KeychainKind::External, KeychainKind::Internal] {
            for index in [0, 1499, 1500, 1501, 1580] {
                let address = branch(&siblings, payment)
                    .peek_address(chain, index)
                    .address;
                let found = selected.find_owned_address(&address.to_string(), 2000);
                if index == 1500 {
                    assert_match(found.unwrap(), if payment { 84 } else { 86 }, chain, index);
                    verify_signature(
                        &selected,
                        &address,
                        if payment { 84 } else { 86 },
                        chain,
                        index,
                    );
                } else {
                    assert!(found.is_none(), "sibling {index} must not be owned");
                    assert!(selected
                        .sign_message(&address.to_string(), "sibling")
                        .is_err());
                }
            }
        }
    }
}

#[test]
fn selected_address_is_indexed_and_survives_persistence_reload() {
    let mut wallet = wallet(DerivationMode::Account, 3, PaymentAddressType::NativeSegwit);
    let payment = wallet.peek_payment_address(80).unwrap();
    let ordinals = wallet.peek_taproot_address(80);
    wallet
        .confirm_dapp_address_selection(&payment.to_string(), &ordinals.to_string(), Some(100))
        .unwrap();
    assert_match(indexed(&wallet, &payment), 84, KeychainKind::External, 80);
    let restored = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
        .with_scheme(AddressScheme::Dual)
        .with_account_index(3)
        .persistence(wallet.export_changeset().unwrap())
        .build()
        .unwrap();
    assert_match(indexed(&restored, &payment), 84, KeychainKind::External, 80);
    assert_match(
        indexed(&restored, &ordinals),
        86,
        KeychainKind::External,
        80,
    );
    verify_signature(&restored, &payment, 84, KeychainKind::External, 80);
}

#[test]
fn known_high_change_address_is_not_limited_to_the_fallback_range() {
    let mut wallet = wallet(DerivationMode::Account, 0, PaymentAddressType::NativeSegwit);
    let address = reveal(&mut wallet, true, KeychainKind::Internal, 1205);
    assert_match(indexed(&wallet, &address), 84, KeychainKind::Internal, 1205);
    verify_signature(&wallet, &address, 84, KeychainKind::Internal, 1205);
}

#[test]
fn foreign_profile_and_account_addresses_are_not_owned() {
    let wallet = wallet(DerivationMode::Account, 3, PaymentAddressType::NativeSegwit);
    for (seed, account) in [([43; 64], 3), ([42; 64], 4)] {
        let foreign = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
            .with_scheme(AddressScheme::Dual)
            .with_account_index(account)
            .build()
            .unwrap();
        assert!(wallet
            .find_owned_address(&foreign.peek_taproot_address(0).to_string(), 2)
            .is_none());
        assert!(wallet
            .find_owned_address(&foreign.peek_payment_address(0).unwrap().to_string(), 2)
            .is_none());
    }
}

#[test]
fn malformed_wrong_network_and_unsupported_scripts_do_not_scan() {
    let wallet = wallet(DerivationMode::Account, 0, PaymentAddressType::NativeSegwit);
    let other_network = WalletBuilder::from_seed(Network::Bitcoin, Seed64::from_array([42; 64]))
        .build()
        .unwrap();
    for address in [
        "not an address".to_string(),
        other_network.peek_taproot_address(0).to_string(),
        Address::p2wsh(&bitcoin::ScriptBuf::new(), Network::Regtest).to_string(),
    ] {
        assert!(wallet
            .find_owned_address_with_fallback(&address, |_, _, _| panic!(
                "invalid address must not scan"
            ))
            .is_none());
    }
}

#[test]
fn unified_wallet_does_not_search_for_payment_only_scripts() {
    let unified = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
        .build()
        .unwrap();
    let dual = wallet(DerivationMode::Account, 0, PaymentAddressType::NativeSegwit);
    assert!(unified
        .find_owned_address_with_fallback(
            &dual.peek_payment_address(0).unwrap().to_string(),
            |_, _, _| panic!("nonexistent branch must not scan")
        )
        .is_none());
    let address = unified.peek_taproot_address(0);
    assert_match(indexed(&unified, &address), 86, KeychainKind::External, 0);
}
