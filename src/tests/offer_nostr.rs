use crate::offer::OfferEnvelopeV1;
use crate::offer_nostr::{NostrOfferEvent, OFFER_EVENT_KIND};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
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
    assert!(event
        .tags
        .iter()
        .any(|tag| tag.len() == 2 && tag[0] == "z" && tag[1] == "zinc-offer-v1"));
    let expected_expiration = offer.expires_at_unix.to_string();
    assert_eq!(
        event.tag_value("expiration"),
        Some(expected_expiration.as_str())
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

    assert!(err
        .to_string()
        .contains("secret key does not match offer seller_pubkey_hex"));
}

#[test]
fn nostr_offer_event_id_and_sig_are_deterministic_for_same_payload() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);

    let event_a =
        NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100).expect("event A");
    let event_b =
        NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100).expect("event B");

    assert_eq!(event_a.id, event_b.id);
    assert_eq!(event_a.sig, event_b.sig);
}

#[test]
fn nostr_offer_event_decode_rejects_expiration_tag_mismatch() {
    let secret_key = SecretKey::from_str(test_secret_hex()).expect("valid secret key");
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);
    let offer_id = offer.offer_id_hex().expect("offer id");
    let content = String::from_utf8(offer.canonical_json().expect("canonical offer json"))
        .expect("utf8 offer json");
    let created_at = 1_710_000_100_u64;
    let tags = vec![
        vec!["z".to_string(), "zinc-offer-v1".to_string()],
        vec!["network".to_string(), offer.network.clone()],
        vec!["inscription".to_string(), offer.inscription_id.clone()],
        vec!["offer_id".to_string(), offer_id],
        vec![
            "expiration".to_string(),
            (offer.expires_at_unix + 1).to_string(),
        ],
        vec!["expires".to_string(), offer.expires_at_unix.to_string()],
    ];
    let payload = serde_json::json!([
        0,
        seller_pubkey_hex,
        created_at,
        OFFER_EVENT_KIND,
        tags,
        content
    ]);
    let event_id = sha256::Hash::hash(
        &serde_json::to_vec(&payload).expect("nostr event id payload serialization"),
    )
    .to_string();
    let digest: [u8; 32] = event_id
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex utf8"))
        .map(|part| u8::from_str_radix(part, 16).expect("hex byte"))
        .collect::<Vec<u8>>()
        .try_into()
        .expect("32-byte digest");
    let message = Message::from_digest(digest);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp
        .sign_schnorr_no_aux_rand(&message, &keypair)
        .to_string();
    let event = NostrOfferEvent {
        id: event_id,
        pubkey: seller_pubkey_hex,
        created_at,
        kind: OFFER_EVENT_KIND,
        tags: payload[4]
            .as_array()
            .expect("tags in payload")
            .iter()
            .map(|tag| {
                tag.as_array()
                    .expect("tag pair")
                    .iter()
                    .map(|v| v.as_str().expect("tag string").to_string())
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<Vec<String>>>(),
        content: payload[5].as_str().expect("content string").to_string(),
        sig: signature,
    };

    let err = event
        .decode_offer()
        .expect_err("expiration mismatch should fail");
    assert!(err
        .to_string()
        .contains("embedded offer expires_at_unix does not match event expiration tag"));
}
