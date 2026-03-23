use crate::offer::OfferEnvelopeV1;
use bdk_wallet::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use std::str::FromStr;

fn sample_offer(seller_pubkey_hex: &str) -> OfferEnvelopeV1 {
    OfferEnvelopeV1 {
        version: 1,
        seller_pubkey_hex: seller_pubkey_hex.to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
            .to_string(),
        ask_sats: 100_000,
        fee_rate_sat_vb: 2,
        psbt_base64: "cHNidP8BAHECAAAAAf//////////////////////////////////////////AAAAAAD9////AqCGAQAAAAAAIgAgx0Jv4z2frfr6f3Ff9rR9lSxDgP3UzrA1n6g0bHTqfQAAAAAAAAAA".to_string(),
        created_at_unix: 1_710_000_000,
        expires_at_unix: 1_710_086_400,
        nonce: 42,
    }
}

fn test_secret_key() -> SecretKey {
    SecretKey::from_str("0001020304050607080900010203040506070809000102030405060708090001")
        .expect("valid test secret key")
}

fn test_public_key_hex() -> String {
    let secp = Secp256k1::new();
    let secret_key = test_secret_key();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    xonly.to_string()
}

#[test]
fn canonical_json_is_stable_for_same_payload() {
    let pubkey = test_public_key_hex();
    let offer_a = sample_offer(&pubkey);
    let offer_b = sample_offer(&pubkey);

    let json_a = offer_a.canonical_json().expect("canonical json A");
    let json_b = offer_b.canonical_json().expect("canonical json B");

    assert_eq!(json_a, json_b);
}

#[test]
fn offer_id_changes_when_payload_changes() {
    let pubkey = test_public_key_hex();
    let offer_a = sample_offer(&pubkey);
    let mut offer_b = sample_offer(&pubkey);
    offer_b.ask_sats += 1;

    let hash_a = offer_a.offer_id_hex().expect("offer id A");
    let hash_b = offer_b.offer_id_hex().expect("offer id B");

    assert_ne!(hash_a, hash_b);
}

#[test]
fn schnorr_signature_verifies_for_matching_pubkey() {
    let pubkey = test_public_key_hex();
    let offer = sample_offer(&pubkey);
    let signature = offer
        .sign_schnorr_hex("0001020304050607080900010203040506070809000102030405060708090001")
        .expect("signed");

    offer
        .verify_schnorr_hex(&signature)
        .expect("signature should verify");
}

#[test]
fn schnorr_signature_rejects_tampered_payload() {
    let pubkey = test_public_key_hex();
    let offer = sample_offer(&pubkey);
    let signature = offer
        .sign_schnorr_hex("0001020304050607080900010203040506070809000102030405060708090001")
        .expect("signed");

    let mut tampered = sample_offer(&pubkey);
    tampered.ask_sats = 150_000;

    assert!(tampered.verify_schnorr_hex(&signature).is_err());
}

#[test]
fn schnorr_signature_rejects_wrong_pubkey() {
    let original_pubkey = test_public_key_hex();
    let offer = sample_offer(&original_pubkey);
    let signature = offer
        .sign_schnorr_hex("0001020304050607080900010203040506070809000102030405060708090001")
        .expect("signed");

    let wrong_secret =
        SecretKey::from_str("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
            .expect("valid secret");
    let secp = Secp256k1::new();
    let wrong_keypair = Keypair::from_secret_key(&secp, &wrong_secret);
    let (wrong_pubkey, _) = XOnlyPublicKey::from_keypair(&wrong_keypair);

    let wrong_offer = sample_offer(&wrong_pubkey.to_string());
    assert!(wrong_offer.verify_schnorr_hex(&signature).is_err());
}
