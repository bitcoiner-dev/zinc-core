use crate::listing::ListingEnvelopeV1;
use crate::listing_nostr::{NostrListingEvent, LISTING_EVENT_KIND};
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

fn sample_listing(seller_pubkey_hex: &str) -> ListingEnvelopeV1 {
    ListingEnvelopeV1 {
        version: 1,
        seller_pubkey_hex: seller_pubkey_hex.to_string(),
        coordinator_pubkey_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
            .to_string(),
        passthrough_outpoint: "25f976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
            .to_string(),
        seller_payout_script_pubkey_hex: "0014751e76e8199196d454941c45d1b3a323f1433bd6".to_string(),
        ask_sats: 100_000,
        postage_sats: 10_000,
        fee_rate_sat_vb: 2,
        tx1_base64: "cHNidP8BAAoCAAAAAQAAAAA=".to_string(),
        sale_psbt_base64: "cHNidP8BAAoCAAAAAQAAAAA=".to_string(),
        recovery_psbt_base64: "cHNidP8BAAoCAAAAAQAAAAA=".to_string(),
        created_at_unix: 1_710_000_000,
        expires_at_unix: 1_710_086_400,
        nonce: 42,
    }
}

#[test]
fn nostr_listing_event_roundtrip_verifies_and_decodes() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);

    let event = NostrListingEvent::from_listing(&listing, test_secret_hex(), 1_710_000_100)
        .expect("event creation should succeed");

    assert_eq!(event.pubkey, seller_pubkey_hex);
    assert_eq!(event.kind, LISTING_EVENT_KIND);
    assert!(event
        .tags
        .iter()
        .any(|tag| tag.len() == 2 && tag[0] == "z" && tag[1] == "zinc-listing-v1"));
    let expected_expiration = listing.expires_at_unix.to_string();
    assert_eq!(
        event.tag_value("expiration"),
        Some(expected_expiration.as_str())
    );

    event.verify().expect("signature should verify");
    let decoded = event.decode_listing().expect("listing should decode");
    assert_eq!(decoded, listing);
}

#[test]
fn nostr_listing_event_verification_fails_when_content_tampered() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);

    let mut event = NostrListingEvent::from_listing(&listing, test_secret_hex(), 1_710_000_100)
        .expect("event creation should succeed");
    event.content.push(' ');

    assert!(event.verify().is_err());
}

#[test]
fn nostr_listing_event_creation_rejects_secret_key_pubkey_mismatch() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);

    let wrong_secret = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let err = NostrListingEvent::from_listing(&listing, wrong_secret, 1_710_000_100)
        .expect_err("mismatch should fail");

    assert!(err
        .to_string()
        .contains("secret key does not match listing seller_pubkey_hex"));
}

#[test]
fn nostr_listing_event_id_and_sig_are_deterministic_for_same_payload() {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);

    let event_a = NostrListingEvent::from_listing(&listing, test_secret_hex(), 1_710_000_100)
        .expect("event A");
    let event_b = NostrListingEvent::from_listing(&listing, test_secret_hex(), 1_710_000_100)
        .expect("event B");

    assert_eq!(event_a.id, event_b.id);
    assert_eq!(event_a.sig, event_b.sig);
}

#[test]
fn nostr_listing_event_decode_rejects_expiration_tag_mismatch() {
    let secret_key = SecretKey::from_str(test_secret_hex()).expect("valid secret key");
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);
    let listing_id = listing.listing_id_hex().expect("listing id");
    let content = String::from_utf8(listing.canonical_json().expect("canonical listing json"))
        .expect("utf8 listing json");
    let created_at = 1_710_000_100_u64;
    let tags = vec![
        vec!["z".to_string(), "zinc-listing-v1".to_string()],
        vec!["network".to_string(), listing.network.clone()],
        vec!["inscription".to_string(), listing.inscription_id.clone()],
        vec!["listing_id".to_string(), listing_id],
        vec!["expiration".to_string(), "1".to_string()],
    ];
    let payload = serde_json::json!([
        0,
        seller_pubkey_hex,
        created_at,
        LISTING_EVENT_KIND,
        tags,
        content
    ]);
    let id = sha256::Hash::hash(&serde_json::to_vec(&payload).expect("payload")).to_string();
    let digest: [u8; 32] = hex::decode(&id)
        .expect("hex")
        .try_into()
        .expect("digest length");
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
        .to_string();

    let event = NostrListingEvent {
        id,
        pubkey: pubkey_hex_from_secret(test_secret_hex()),
        created_at,
        kind: LISTING_EVENT_KIND,
        tags,
        content,
        sig,
    };

    let err = event.decode_listing().expect_err("expiration mismatch");
    assert!(err.to_string().contains("expiration tag"));
}
