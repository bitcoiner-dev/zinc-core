use crate::sign_intent::{
    build_signed_pairing_ack, pubkey_hex_from_secret_key, validate_signed_pairing_ack_json,
    validate_signed_pairing_request_json, validate_signed_sign_intent_json,
    validate_signed_sign_intent_receipt_json, verify_pairing_approval, BuildBuyerOfferIntentV1,
    CapabilityPolicyV1, PairingAckDecisionV1, PairingAckV1, PairingRequestV1, SignIntentActionV1,
    SignIntentPayloadV1, SignIntentReceiptStatusV1, SignIntentReceiptV1, SignIntentV1,
    SignedPairingAckV1, SignedPairingRequestV1, SignedSignIntentReceiptV1, SignedSignIntentV1,
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
