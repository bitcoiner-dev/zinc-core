#![cfg(not(target_arch = "wasm32"))]

use crate::listing::ListingEnvelopeV1;
use crate::listing_nostr::NostrListingEvent;
use crate::listing_relay::NostrListingRelayClient;
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

fn sample_event() -> NostrListingEvent {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let listing = sample_listing(&seller_pubkey_hex);
    NostrListingEvent::from_listing(&listing, test_secret_hex(), 1_710_000_100)
        .expect("valid event")
}

#[test]
fn event_frame_contains_nostr_listing_event_payload() {
    let event = sample_event();
    let frame = NostrListingRelayClient::event_frame(&event).expect("frame");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("json frame");

    assert_eq!(parsed[0], "EVENT");
    assert_eq!(parsed[1]["id"], event.id);
    assert_eq!(parsed[1]["pubkey"], event.pubkey);
}

#[test]
fn req_frame_targets_listing_kind_and_schema_tag() {
    let frame = NostrListingRelayClient::req_frame("sub-1", 25).expect("frame");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("json frame");

    assert_eq!(parsed[0], "REQ");
    assert_eq!(parsed[1], "sub-1");
    assert_eq!(
        parsed[2]["kinds"][0],
        crate::listing_nostr::LISTING_EVENT_KIND
    );
    assert_eq!(parsed[2]["#z"][0], "zinc-listing-v1");
    assert_eq!(parsed[2]["limit"], 25);
}

#[test]
fn parse_ok_frame_extracts_acceptance_and_message() {
    let ok =
        NostrListingRelayClient::parse_ok_frame(r#"["OK","abcd1234",true,"accepted"]"#, "abcd1234")
            .expect("valid ok frame");

    assert!(ok.0);
    assert_eq!(ok.1, "accepted");
}

#[test]
fn parse_event_frame_requires_matching_subscription() {
    let event = sample_event();
    let frame = format!(
        r#"["EVENT","sub-expected",{}]"#,
        serde_json::to_string(&event).expect("serialize event")
    );

    assert!(NostrListingRelayClient::parse_event_frame(&frame, "sub-other").is_none());
    assert!(NostrListingRelayClient::parse_event_frame(&frame, "sub-expected").is_some());
}

#[test]
fn wss_transport_compiles_with_tls_connect_api() {
    let _ = tokio_tungstenite::connect_async_tls_with_config::<&str>;
}
