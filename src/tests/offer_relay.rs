#![cfg(not(target_arch = "wasm32"))]

use crate::offer::OfferEnvelopeV1;
use crate::offer_nostr::NostrOfferEvent;
use crate::offer_relay::NostrRelayClient;
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

fn sample_event() -> NostrOfferEvent {
    let seller_pubkey_hex = pubkey_hex_from_secret(test_secret_hex());
    let offer = sample_offer(&seller_pubkey_hex);
    NostrOfferEvent::from_offer(&offer, test_secret_hex(), 1_710_000_100).expect("valid event")
}

#[test]
fn event_frame_contains_nostr_event_payload() {
    let event = sample_event();
    let frame = NostrRelayClient::event_frame(&event).expect("frame");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("json frame");

    assert_eq!(parsed[0], "EVENT");
    assert_eq!(parsed[1]["id"], event.id);
    assert_eq!(parsed[1]["pubkey"], event.pubkey);
}

#[test]
fn req_frame_targets_offer_kind_and_schema_tag() {
    let frame = NostrRelayClient::req_frame("sub-1", 25).expect("frame");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("json frame");

    assert_eq!(parsed[0], "REQ");
    assert_eq!(parsed[1], "sub-1");
    assert_eq!(parsed[2]["kinds"][0], crate::offer_nostr::OFFER_EVENT_KIND);
    assert_eq!(parsed[2]["#z"][0], "zinc-offer-v1");
    assert_eq!(parsed[2]["limit"], 25);
}

#[test]
fn parse_ok_frame_extracts_acceptance_and_message() {
    let ok = NostrRelayClient::parse_ok_frame(
        r#"["OK","abcd1234",true,"accepted"]"#,
        "abcd1234",
    )
    .expect("valid ok frame");

    assert_eq!(ok.0, true);
    assert_eq!(ok.1, "accepted");
}

#[test]
fn parse_event_frame_requires_matching_subscription() {
    let event = sample_event();
    let frame = format!(
        r#"["EVENT","sub-expected",{}]"#,
        serde_json::to_string(&event).expect("serialize event")
    );

    assert!(NostrRelayClient::parse_event_frame(&frame, "sub-other").is_none());
    assert!(NostrRelayClient::parse_event_frame(&frame, "sub-expected").is_some());
}

#[test]
fn wss_transport_compiles_with_tls_connect_api() {
    let _ = tokio_tungstenite::connect_async_tls_with_config::<&str>;
}
