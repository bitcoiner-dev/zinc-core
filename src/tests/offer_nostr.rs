use crate::offer::OfferEnvelopeV1;
use crate::offer_nostr::{NostrOfferEvent, OFFER_EVENT_KIND};
use bdk_wallet::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use std::str::FromStr;

fn test_secret_hex() -> &'static str {
    "0001020304050607080900010203040506070809000102030405060708090001"
}

fn pubkey_hex_from_secret(secret_hex: &str) -> String {
    let secret_key = SecretKey::from_str(secret_hex).expect("valid secret key");
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    xonly.to_string()
}

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

#[test]
fn nostr_offer_event_roundtrip_verifies_and_decodes() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);

    let event = NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100)
        .expect("event creation should succeed");

    assert_eq!(event.pubkey, seller_pubkey_hex);
    assert_eq!(event.kind, OFFER_EVENT_KIND);
    assert!(
        event
            .tags
            .iter()
            .any(|tag| tag.len() == 2 && tag[0] == "z" && tag[1] == "zinc-offer-v1")
    );

    event.verify().expect("signature should verify");
    let decoded = event.decode_offer().expect("offer should decode");
    assert_eq!(decoded, offer);
}

#[test]
fn nostr_offer_event_verification_fails_when_content_tampered() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);

    let mut event = NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100)
        .expect("event creation should succeed");
    event.content.push(' ');

    assert!(event.verify().is_err());
}

#[test]
fn nostr_offer_event_creation_rejects_secret_key_pubkey_mismatch() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);

    let wrong_secret = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let err = NostrOfferEvent::from_offer(&offer, wrong_secret, 1_710_000_100)
        .expect_err("mismatch should fail");

    assert!(
        err.to_string()
            .contains("secret key does not match offer seller_pubkey_hex")
    );
}

#[test]
fn nostr_offer_event_id_and_sig_are_deterministic_for_same_payload() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);

    let event_a = NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100)
        .expect("event A");
    let event_b = NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100)
        .expect("event B");

    assert_eq!(event_a.id, event_b.id);
    assert_eq!(event_a.sig, event_b.sig);
}
