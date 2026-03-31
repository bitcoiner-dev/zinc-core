use crate::sign_intent::{
    build_signed_pairing_ack, build_signed_pairing_ack_with_granted,
    build_signed_pairing_complete_receipt, pairing_tag_hash_hex, pubkey_hex_from_secret_key,
    validate_pairing_ack_envelope_json, validate_signed_pairing_complete_receipt_json,
    validate_nostr_transport_event_json,
    validate_signed_pairing_ack_json, validate_signed_pairing_request_json,
    validate_signed_sign_intent_json, validate_signed_sign_intent_receipt_json,
    verify_pairing_approval, BuildBuyerOfferIntentV1, CapabilityPolicyV1,
    decode_pairing_ack_envelope_event, decode_signed_pairing_complete_receipt_event,
    pairing_transport_tags, NostrTransportEventV1, PairingAckDecisionV1, PairingAckEnvelopeV1,
    PairingAckV1, PairingRequestV1, PAIRING_TRANSPORT_EVENT_KIND,
    PairingCompleteReceiptStatusV1, PairingCompleteReceiptV1, SignIntentActionV1,
    SignIntentPayloadV1, SignIntentReceiptStatusV1, SignIntentReceiptV1, SignIntentV1,
    SignedPairingAckV1, SignedPairingCompleteReceiptV1, SignedPairingRequestV1,
    SignedSignIntentReceiptV1, SignedSignIntentV1, NOSTR_PAIRING_ACK_TYPE_TAG_VALUE,
    NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE, NOSTR_SIGN_INTENT_APP_TAG_VALUE,
};

fn agent_secret_hex() -> &'static str {
    "0001020304050607080900010203040506070809000102030405060708090001"
}

fn wallet_secret_hex() -> &'static str {
    "0102030405060708090001020304050607080900010203040506070809000102"
}

fn sample_capability_policy() -> CapabilityPolicyV1 {
    CapabilityPolicyV1 {
        allowed_actions: vec![
            SignIntentActionV1::BuildBuyerOffer,
            SignIntentActionV1::SignSellerInput,
        ],
        max_sats_per_intent: Some(300_000),
        daily_spend_limit_sats: Some(900_000),
        max_fee_rate_sat_vb: Some(20),
        allowed_networks: vec!["regtest".to_string()],
    }
}

fn sample_pairing_request() -> PairingRequestV1 {
    PairingRequestV1 {
        version: 1,
        agent_pubkey_hex: pubkey_hex_from_secret_key(agent_secret_hex()).expect("agent pubkey"),
        challenge_nonce: "pairing-nonce-v1".to_string(),
        created_at_unix: 1_710_000_000,
        expires_at_unix: 1_710_000_600,
        relays: vec!["wss://relay.example".to_string()],
        requested_capabilities: sample_capability_policy(),
    }
}

fn sample_approved_ack(request: &PairingRequestV1) -> PairingAckV1 {
    PairingAckV1 {
        version: 1,
        pairing_id: request.pairing_id_hex().expect("pairing id"),
        challenge_nonce: request.challenge_nonce.clone(),
        agent_pubkey_hex: request.agent_pubkey_hex.clone(),
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: request.created_at_unix + 10,
        expires_at_unix: request.expires_at_unix + 300,
        decision: PairingAckDecisionV1::Approved,
        granted_capabilities: Some(sample_capability_policy()),
        rejection_reason: None,
    }
}

#[test]
fn signed_pairing_request_roundtrip_and_deterministic_id() {
    let request = sample_pairing_request();

    let signed_a = SignedPairingRequestV1::new(request.clone(), agent_secret_hex())
        .expect("signed pairing request A");
    let signed_b =
        SignedPairingRequestV1::new(request, agent_secret_hex()).expect("signed pairing request B");

    signed_a.verify().expect("verify signed request");
    assert_eq!(
        signed_a.pairing_id_hex().expect("pairing id A"),
        signed_b.pairing_id_hex().expect("pairing id B")
    );
}

#[test]
fn signed_pairing_request_rejects_tampering() {
    let mut signed =
        SignedPairingRequestV1::new(sample_pairing_request(), agent_secret_hex()).expect("signed");

    signed.request.challenge_nonce = "tampered-nonce".to_string();
    assert!(signed.verify().is_err());
}

#[test]
fn pairing_ack_rules_enforced_for_approved() {
    let request = sample_pairing_request();
    let pairing_id = request.pairing_id_hex().expect("pairing id");

    let invalid_ack = PairingAckV1 {
        version: 1,
        pairing_id,
        challenge_nonce: request.challenge_nonce,
        agent_pubkey_hex: request.agent_pubkey_hex,
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: 1_710_000_010,
        expires_at_unix: 1_710_000_900,
        decision: PairingAckDecisionV1::Approved,
        granted_capabilities: None,
        rejection_reason: None,
    };

    let err = invalid_ack
        .canonical_json()
        .expect_err("approved ack without capability must fail");
    assert!(err
        .to_string()
        .contains("approved pairing ack must include granted_capabilities"));
}

#[test]
fn signed_sign_intent_and_receipt_roundtrip() {
    let request = sample_pairing_request();
    let pairing_id = request.pairing_id_hex().expect("pairing id");

    let intent = SignIntentV1 {
        version: 1,
        pairing_id: pairing_id.clone(),
        agent_pubkey_hex: request.agent_pubkey_hex.clone(),
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        network: "regtest".to_string(),
        created_at_unix: 1_710_000_020,
        expires_at_unix: 1_710_000_920,
        nonce: 7,
        payload: SignIntentPayloadV1::BuildBuyerOffer(BuildBuyerOfferIntentV1 {
            inscription_id: "inscription-123".to_string(),
            seller_outpoint: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
                .to_string(),
            ask_sats: 100_000,
            fee_rate_sat_vb: 2,
        }),
    };

    let signed_intent = SignedSignIntentV1::new(intent, agent_secret_hex()).expect("signed intent");
    signed_intent.verify().expect("verify signed intent");

    let intent_id = signed_intent.intent_id_hex().expect("intent id");

    let receipt = SignIntentReceiptV1 {
        version: 1,
        intent_id,
        pairing_id,
        signer_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: 1_710_000_030,
        status: SignIntentReceiptStatusV1::Approved,
        signed_psbt_base64: Some(
            "cHNidP8BAHECAAAAAf//////////////////////////////////////////AAAAAAD9////AqCGAQAAAAAAIgAgx0Jv4z2frfr6f3Ff9rR9lSxDgP3UzrA1n6g0bHTqfQAAAAAAAAAA"
                .to_string(),
        ),
        artifact_json: None,
        error_message: None,
    };

    let signed_receipt =
        SignedSignIntentReceiptV1::new(receipt, wallet_secret_hex()).expect("signed receipt");
    signed_receipt.verify().expect("verify signed receipt");
}

#[test]
fn signed_json_helpers_verify_all_payloads() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let pairing_id = signed_request.pairing_id_hex().expect("pairing id");

    let ack = PairingAckV1 {
        version: 1,
        pairing_id: pairing_id.clone(),
        challenge_nonce: request.challenge_nonce.clone(),
        agent_pubkey_hex: request.agent_pubkey_hex.clone(),
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: 1_710_000_050,
        expires_at_unix: 1_710_000_950,
        decision: PairingAckDecisionV1::Approved,
        granted_capabilities: Some(sample_capability_policy()),
        rejection_reason: None,
    };
    let signed_ack = SignedPairingAckV1::new(ack, wallet_secret_hex()).expect("signed ack");

    let intent = SignIntentV1 {
        version: 1,
        pairing_id: pairing_id.clone(),
        agent_pubkey_hex: request.agent_pubkey_hex,
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        network: "regtest".to_string(),
        created_at_unix: 1_710_000_060,
        expires_at_unix: 1_710_000_960,
        nonce: 88,
        payload: SignIntentPayloadV1::BuildBuyerOffer(BuildBuyerOfferIntentV1 {
            inscription_id: "inscription-123".to_string(),
            seller_outpoint: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
                .to_string(),
            ask_sats: 120_000,
            fee_rate_sat_vb: 2,
        }),
    };
    let signed_intent = SignedSignIntentV1::new(intent, agent_secret_hex()).expect("signed intent");
    let intent_id = signed_intent.intent_id_hex().expect("intent id");

    let receipt = SignIntentReceiptV1 {
        version: 1,
        intent_id,
        pairing_id,
        signer_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: 1_710_000_070,
        status: SignIntentReceiptStatusV1::Rejected,
        signed_psbt_base64: None,
        artifact_json: None,
        error_message: Some("user rejected".to_string()),
    };
    let signed_receipt =
        SignedSignIntentReceiptV1::new(receipt, wallet_secret_hex()).expect("signed receipt");

    let request_json = serde_json::to_string(&signed_request).expect("request json");
    let ack_json = serde_json::to_string(&signed_ack).expect("ack json");
    let intent_json = serde_json::to_string(&signed_intent).expect("intent json");
    let receipt_json = serde_json::to_string(&signed_receipt).expect("receipt json");

    assert!(validate_signed_pairing_request_json(&request_json).is_ok());
    assert!(validate_signed_pairing_ack_json(&ack_json).is_ok());
    assert!(validate_signed_sign_intent_json(&intent_json).is_ok());
    assert!(validate_signed_sign_intent_receipt_json(&receipt_json).is_ok());
}

#[test]
fn verify_pairing_approval_accepts_valid_request_and_ack() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let signed_ack = SignedPairingAckV1::new(sample_approved_ack(&request), wallet_secret_hex())
        .expect("signed ack");

    let approval = verify_pairing_approval(&signed_request, &signed_ack, 1_710_000_100)
        .expect("pairing approval");
    assert_eq!(
        approval.pairing_id,
        request.pairing_id_hex().expect("pairing id")
    );
    assert_eq!(approval.agent_pubkey_hex, request.agent_pubkey_hex);
}

#[test]
fn verify_pairing_approval_rejects_nonce_mismatch() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let mut ack = sample_approved_ack(&request);
    ack.challenge_nonce = "different-nonce".to_string();
    let signed_ack = SignedPairingAckV1::new(ack, wallet_secret_hex()).expect("signed ack");

    let err = verify_pairing_approval(&signed_request, &signed_ack, 1_710_000_100)
        .expect_err("approval should fail");
    assert!(err
        .to_string()
        .contains("pairing ack challenge_nonce does not match pairing request"));
}

#[test]
fn verify_pairing_approval_rejects_capability_escalation() {
    let mut request = sample_pairing_request();
    request.requested_capabilities.allowed_actions = vec![SignIntentActionV1::SignSellerInput];
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");

    let mut ack = sample_approved_ack(&request);
    let mut granted = ack.granted_capabilities.expect("granted");
    granted.allowed_actions = vec![SignIntentActionV1::BuildBuyerOffer];
    ack.granted_capabilities = Some(granted);
    let signed_ack = SignedPairingAckV1::new(ack, wallet_secret_hex()).expect("signed ack");

    let err = verify_pairing_approval(&signed_request, &signed_ack, 1_710_000_100)
        .expect_err("approval should fail");
    assert!(err
        .to_string()
        .contains("granted capability action `BuildBuyerOffer` was not requested"));
}

#[test]
fn build_signed_pairing_ack_approves_request_with_subset_safe_defaults() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");

    let signed_ack =
        build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
            .expect("build signed ack");

    assert!(matches!(
        signed_ack.ack.decision,
        PairingAckDecisionV1::Approved
    ));
    assert_eq!(
        signed_ack.ack.granted_capabilities,
        Some(request.requested_capabilities.clone())
    );
    assert_eq!(
        signed_ack.ack.pairing_id,
        signed_request.pairing_id_hex().expect("pairing id")
    );

    let approval = verify_pairing_approval(&signed_request, &signed_ack, 1_710_000_100)
        .expect("approval should verify");
    assert_eq!(approval.agent_pubkey_hex, request.agent_pubkey_hex);
}

#[test]
fn build_signed_pairing_ack_rejects_expired_request() {
    let mut request = sample_pairing_request();
    request.expires_at_unix = 1_710_000_050;
    let signed_request =
        SignedPairingRequestV1::new(request, agent_secret_hex()).expect("signed request");

    let err = build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
        .expect_err("expired request should fail");
    assert!(err
        .to_string()
        .contains("pairing request expired before ack creation"));
}

#[test]
fn build_signed_pairing_ack_accepts_explicit_subset_grants() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request, agent_secret_hex()).expect("signed request");

    let granted = CapabilityPolicyV1 {
        allowed_actions: vec![SignIntentActionV1::SignSellerInput],
        max_sats_per_intent: Some(100_000),
        daily_spend_limit_sats: Some(250_000),
        max_fee_rate_sat_vb: Some(10),
        allowed_networks: vec!["regtest".to_string()],
    };

    let signed_ack = build_signed_pairing_ack_with_granted(
        &signed_request,
        wallet_secret_hex(),
        1_710_000_100,
        600,
        Some(granted.clone()),
    )
    .expect("build signed ack");

    assert_eq!(signed_ack.ack.granted_capabilities, Some(granted));
}

#[test]
fn build_signed_pairing_ack_rejects_explicit_capability_escalation() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request, agent_secret_hex()).expect("signed request");

    let escalation = CapabilityPolicyV1 {
        allowed_actions: vec![SignIntentActionV1::BuildBuyerOffer],
        max_sats_per_intent: Some(400_000),
        daily_spend_limit_sats: Some(1_000_000),
        max_fee_rate_sat_vb: Some(30),
        allowed_networks: vec!["regtest".to_string()],
    };

    let err = build_signed_pairing_ack_with_granted(
        &signed_request,
        wallet_secret_hex(),
        1_710_000_100,
        600,
        Some(escalation),
    )
    .expect_err("escalation must fail");

    assert!(err
        .to_string()
        .contains("granted max_sats_per_intent=400000 exceeds requested limit 300000"));
}

#[test]
fn pairing_tag_hash_is_deterministic_hex64() {
    let pairing_id = "a".repeat(64);
    let first = pairing_tag_hash_hex(&pairing_id).expect("pairing tag hash first");
    let second = pairing_tag_hash_hex(&pairing_id).expect("pairing tag hash second");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn pairing_ack_envelope_validates_embedded_ack_and_tags() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let signed_ack =
        build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
            .expect("signed ack");

    let envelope = PairingAckEnvelopeV1::new(signed_ack, 1_710_000_101).expect("envelope");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.app_tag, NOSTR_SIGN_INTENT_APP_TAG_VALUE);
    assert_eq!(envelope.type_tag, NOSTR_PAIRING_ACK_TYPE_TAG_VALUE);
    assert_eq!(
        envelope.pairing_tag_hash_hex,
        pairing_tag_hash_hex(&request.pairing_id_hex().expect("pairing id"))
            .expect("pairing tag hash")
    );

    let envelope_json = serde_json::to_string(&envelope).expect("envelope json");
    let envelope_id = validate_pairing_ack_envelope_json(&envelope_json).expect("validate envelope");
    assert_eq!(envelope_id.len(), 64);
}

#[test]
fn pairing_ack_envelope_rejects_pairing_hash_mismatch() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request, agent_secret_hex()).expect("signed request");
    let signed_ack =
        build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
            .expect("signed ack");
    let mut envelope = PairingAckEnvelopeV1::new(signed_ack, 1_710_000_101).expect("envelope");
    envelope.pairing_tag_hash_hex = "f".repeat(64);

    let envelope_json = serde_json::to_string(&envelope).expect("envelope json");
    let err = validate_pairing_ack_envelope_json(&envelope_json).expect_err("must fail");
    assert!(err
        .to_string()
        .contains("pairing ack envelope pairing_tag_hash_hex does not match embedded pairing_id"));
}

#[test]
fn signed_pairing_complete_receipt_roundtrip_and_builder() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let signed_ack =
        build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
            .expect("signed ack");

    let signed_receipt = build_signed_pairing_complete_receipt(
        &signed_request,
        &signed_ack,
        agent_secret_hex(),
        1_710_000_120,
    )
    .expect("signed pairing complete receipt");
    signed_receipt.verify().expect("verify signed receipt");
    assert_eq!(
        signed_receipt.receipt.status,
        PairingCompleteReceiptStatusV1::Confirmed
    );

    let receipt_json = serde_json::to_string(&signed_receipt).expect("receipt json");
    let receipt_id =
        validate_signed_pairing_complete_receipt_json(&receipt_json).expect("validate receipt");
    assert_eq!(receipt_id.len(), 64);

    let rejected_receipt = PairingCompleteReceiptV1 {
        version: 1,
        pairing_id: signed_request.pairing_id_hex().expect("pairing id"),
        ack_id: signed_ack.ack_id_hex().expect("ack id"),
        challenge_nonce: request.challenge_nonce,
        agent_pubkey_hex: request.agent_pubkey_hex,
        wallet_pubkey_hex: pubkey_hex_from_secret_key(wallet_secret_hex()).expect("wallet pubkey"),
        created_at_unix: 1_710_000_121,
        status: PairingCompleteReceiptStatusV1::Rejected,
        error_message: Some("operator cancelled".to_string()),
    };
    let signed_rejected =
        SignedPairingCompleteReceiptV1::new(rejected_receipt, agent_secret_hex())
            .expect("signed rejected receipt");
    signed_rejected.verify().expect("verify rejected receipt");
}

#[test]
fn nostr_transport_event_roundtrip_for_ack_and_complete_receipt() {
    let request = sample_pairing_request();
    let signed_request =
        SignedPairingRequestV1::new(request.clone(), agent_secret_hex()).expect("signed request");
    let signed_ack =
        build_signed_pairing_ack(&signed_request, wallet_secret_hex(), 1_710_000_100, 600)
            .expect("signed ack");
    let envelope = PairingAckEnvelopeV1::new(signed_ack.clone(), 1_710_000_101).expect("envelope");
    let envelope_json = serde_json::to_string(&envelope).expect("envelope json");
    let ack_tags = pairing_transport_tags(
        NOSTR_PAIRING_ACK_TYPE_TAG_VALUE,
        &signed_ack.ack.pairing_id,
        &signed_ack.ack.agent_pubkey_hex,
    )
    .expect("ack tags");
    let ack_event = NostrTransportEventV1::new(
        PAIRING_TRANSPORT_EVENT_KIND,
        ack_tags,
        envelope_json,
        1_710_000_110,
        wallet_secret_hex(),
    )
    .expect("ack event");
    let ack_event_json = serde_json::to_string(&ack_event).expect("ack event json");
    assert!(validate_nostr_transport_event_json(&ack_event_json).is_ok());
    let decoded_envelope = decode_pairing_ack_envelope_event(&ack_event).expect("decode ack envelope");
    assert_eq!(
        decoded_envelope.signed_ack.ack.pairing_id,
        signed_request.pairing_id_hex().expect("pairing id")
    );

    let signed_complete = build_signed_pairing_complete_receipt(
        &signed_request,
        &signed_ack,
        agent_secret_hex(),
        1_710_000_120,
    )
    .expect("signed complete");
    let complete_json = serde_json::to_string(&signed_complete).expect("complete json");
    let complete_tags = pairing_transport_tags(
        NOSTR_PAIRING_COMPLETE_RECEIPT_TYPE_TAG_VALUE,
        &signed_complete.receipt.pairing_id,
        &signed_complete.receipt.wallet_pubkey_hex,
    )
    .expect("complete tags");
    let complete_event = NostrTransportEventV1::new(
        PAIRING_TRANSPORT_EVENT_KIND,
        complete_tags,
        complete_json,
        1_710_000_121,
        agent_secret_hex(),
    )
    .expect("complete event");
    let decoded_complete =
        decode_signed_pairing_complete_receipt_event(&complete_event).expect("decode complete");
    assert_eq!(
        decoded_complete.receipt.status,
        PairingCompleteReceiptStatusV1::Confirmed
    );
}
