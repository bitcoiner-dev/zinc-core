use crate::listing::{
    create_listing, finalize_listing_purchase, finalize_listing_sale, passthrough_script_pubkey,
    passthrough_tapscript, prepare_listing_sale_signature, sign_listing_coordinator_psbt,
    sign_listing_sale_psbt, CreateListingPurchaseRequest, CreateListingRequest,
    FinalizeListingPurchaseRequest, ListingBuyerFundingInput, ListingEnvelopeV1,
    LISTING_SALE_SIGHASH_U8,
};
use crate::{AddressScheme, Seed64, WalletBuilder};
use base64::Engine;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bdk_wallet::bitcoin::taproot::TapLeafHash;
use bdk_wallet::bitcoin::{
    absolute, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bdk_wallet::chain::ConfirmationBlockTime;
use std::str::FromStr;
use std::{collections::BTreeMap, collections::HashSet};

const SELLER_PUBKEY_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SELLER_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const WRONG_SELLER_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";
const COORDINATOR_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
const WRONG_COORDINATOR_SECRET_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000004";
const COORDINATOR_PUBKEY_HEX: &str =
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const SELLER_PAYOUT_SCRIPT_HEX: &str =
    "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ASK_SATS: u64 = 100_000;
const POSTAGE_SATS: u64 = 330;

fn sample_txid(byte: u8) -> Txid {
    Txid::from_slice(&[byte; 32]).expect("valid txid")
}

fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[31] = uid;
    let dummy_txid = Txid::from_byte_array(hash_bytes);
    Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(dummy_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey,
        }],
    }
}

fn funded_unified_wallet(mark_ordinals_verified: bool) -> crate::ZincWallet {
    let seed = [7u8; 64];
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Unified)
        .build()
        .expect("wallet build");

    if mark_ordinals_verified {
        wallet.apply_verified_ordinals_update(Vec::new(), HashSet::new(), Vec::new());
    }

    let receive_script = wallet
        .vault_wallet
        .reveal_next_address(bdk_wallet::KeychainKind::External)
        .address
        .script_pubkey();
    let tx = create_dummy_tx(250_000, receive_script, 19);
    let mut graph = bdk_wallet::chain::TxGraph::default();
    let _ = graph.insert_tx(tx.clone());
    let _ = graph.insert_anchor(
        tx.compute_txid(),
        ConfirmationBlockTime {
            block_id: bdk_wallet::chain::BlockId {
                height: 101,
                hash: bdk_wallet::bitcoin::BlockHash::all_zeros(),
            },
            confirmation_time: 1001,
        },
    );
    let mut last_active = BTreeMap::new();
    last_active.insert(bdk_wallet::KeychainKind::External, 5);
    wallet
        .vault_wallet
        .apply_update(bdk_wallet::Update {
            tx_update: graph.into(),
            chain: Default::default(),
            last_active_indices: last_active,
        })
        .expect("apply update");

    wallet
}

fn sample_listing(psbt_base64: String) -> ListingEnvelopeV1 {
    ListingEnvelopeV1 {
        version: 1,
        seller_pubkey_hex: SELLER_PUBKEY_HEX.to_string(),
        coordinator_pubkey_hex: COORDINATOR_PUBKEY_HEX.to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: OutPoint::new(sample_txid(0x11), 0).to_string(),
        passthrough_outpoint: OutPoint::new(sample_txid(0x22), 0).to_string(),
        seller_payout_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        ask_sats: ASK_SATS,
        postage_sats: POSTAGE_SATS,
        fee_rate_sat_vb: 1,
        tx1_base64: "tx1-placeholder".to_string(),
        sale_psbt_base64: psbt_base64,
        recovery_psbt_base64: "tx3-placeholder".to_string(),
        created_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_003_600,
        nonce: 7,
    }
}

fn sample_create_listing_request() -> CreateListingRequest {
    CreateListingRequest {
        seller_pubkey_hex: SELLER_PUBKEY_HEX.to_string(),
        coordinator_pubkey_hex: COORDINATOR_PUBKEY_HEX.to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: OutPoint::new(sample_txid(0x11), 0),
        seller_prevout: TxOut {
            value: Amount::from_sat(POSTAGE_SATS),
            script_pubkey: seller_payout_script(),
        },
        seller_payout_script_pubkey: seller_payout_script(),
        recovery_script_pubkey: seller_payout_script(),
        ask_sats: ASK_SATS,
        fee_rate_sat_vb: 1,
        created_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_003_600,
        nonce: 7,
    }
}

fn sale_psbt_base64(
    passthrough_outpoint: OutPoint,
    output_value: u64,
    output_script: ScriptBuf,
    sighash: Option<u8>,
    seller_signed: bool,
) -> String {
    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: passthrough_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: output_script,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(POSTAGE_SATS),
        script_pubkey: ScriptBuf::new(),
    });
    psbt.inputs[0].sighash_type =
        sighash.map(|raw| bdk_wallet::bitcoin::psbt::PsbtSighashType::from_u32(u32::from(raw)));

    if seller_signed {
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[b"seller-sig".to_vec()]));
    }

    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

fn seller_payout_script() -> ScriptBuf {
    ScriptBuf::from_hex(SELLER_PAYOUT_SCRIPT_HEX).expect("script hex")
}

fn buyer_receive_script() -> ScriptBuf {
    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    ScriptBuf::new_p2tr(&Secp256k1::verification_only(), coordinator, None)
}

fn decode_psbt(encoded: &str) -> Psbt {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .expect("base64");
    Psbt::deserialize(&bytes).expect("psbt")
}

fn encode_psbt(psbt: &Psbt) -> String {
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

fn input_has_signature(input: &bdk_wallet::bitcoin::psbt::Input) -> bool {
    input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
}

fn decode_listing_psbts(listing: &ListingEnvelopeV1) -> (Psbt, Psbt, Psbt) {
    (
        decode_psbt(&listing.tx1_base64),
        decode_psbt(&listing.sale_psbt_base64),
        decode_psbt(&listing.recovery_psbt_base64),
    )
}

#[test]
fn create_listing_builds_tx1_to_passthrough_output() {
    let request = sample_create_listing_request();
    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    let expected_passthrough_script = passthrough_script_pubkey(seller, coordinator);

    let created = create_listing(&request).expect("listing create");
    let (tx1, sale, recovery) = decode_listing_psbts(&created.listing);

    assert_eq!(tx1.unsigned_tx.input.len(), 1);
    assert_eq!(
        tx1.unsigned_tx.input[0].previous_output,
        request.seller_outpoint
    );
    assert_eq!(tx1.unsigned_tx.output.len(), 1);
    assert_eq!(
        tx1.unsigned_tx.output[0].script_pubkey,
        expected_passthrough_script
    );
    assert_eq!(
        tx1.unsigned_tx.output[0].value,
        Amount::from_sat(POSTAGE_SATS)
    );
    assert_eq!(
        created.passthrough_outpoint,
        OutPoint::new(tx1.unsigned_tx.compute_txid(), 0)
    );
    assert_eq!(
        created.listing.passthrough_outpoint,
        created.passthrough_outpoint.to_string()
    );
    assert_eq!(
        sale.unsigned_tx.input[0].previous_output,
        created.passthrough_outpoint
    );
    assert_eq!(
        recovery.unsigned_tx.input[0].previous_output,
        created.passthrough_outpoint
    );
}

#[test]
fn create_listing_transport_request_converts_app_boundary_shape() {
    let request = crate::CreateListingTransportRequest {
        seller_pubkey_hex: SELLER_PUBKEY_HEX.to_string(),
        coordinator_pubkey_hex: COORDINATOR_PUBKEY_HEX.to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: OutPoint::new(sample_txid(0x11), 0).to_string(),
        seller_prevout_value_sats: POSTAGE_SATS,
        seller_prevout_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        seller_payout_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        recovery_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        ask_sats: ASK_SATS,
        fee_rate_sat_vb: 1,
        created_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_003_600,
        nonce: 7,
    };

    let converted = CreateListingRequest::try_from(request).expect("transport conversion");

    assert_eq!(converted.seller_pubkey_hex, SELLER_PUBKEY_HEX);
    assert_eq!(converted.coordinator_pubkey_hex, COORDINATOR_PUBKEY_HEX);
    assert_eq!(
        converted.seller_prevout.value,
        Amount::from_sat(POSTAGE_SATS)
    );
    assert_eq!(
        converted.seller_prevout.script_pubkey,
        seller_payout_script()
    );
    assert_eq!(
        converted.seller_payout_script_pubkey,
        seller_payout_script()
    );
    assert_eq!(converted.recovery_script_pubkey, seller_payout_script());
}

#[test]
fn create_listing_transport_request_rejects_bad_script_hex() {
    let request = crate::CreateListingTransportRequest {
        seller_pubkey_hex: SELLER_PUBKEY_HEX.to_string(),
        coordinator_pubkey_hex: COORDINATOR_PUBKEY_HEX.to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: OutPoint::new(sample_txid(0x11), 0).to_string(),
        seller_prevout_value_sats: POSTAGE_SATS,
        seller_prevout_script_pubkey_hex: "not-hex".to_string(),
        seller_payout_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        recovery_script_pubkey_hex: SELLER_PAYOUT_SCRIPT_HEX.to_string(),
        ask_sats: ASK_SATS,
        fee_rate_sat_vb: 1,
        created_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_003_600,
        nonce: 7,
    };

    let err = CreateListingRequest::try_from(request).expect_err("bad script hex rejected");

    assert!(err.to_string().contains("seller_prevout_script_pubkey_hex"));
}

#[test]
fn create_listing_builds_sale_psbt_that_passes_strict_sale_validation() {
    let request = sample_create_listing_request();
    let created = create_listing(&request).expect("listing create");
    let (_tx1, sale, _recovery) = decode_listing_psbts(&created.listing);

    assert_eq!(sale.unsigned_tx.input.len(), 1);
    assert_eq!(sale.unsigned_tx.output.len(), 1);
    assert_eq!(
        sale.inputs[0].witness_utxo,
        Some(created.passthrough_txout.clone())
    );
    assert_eq!(
        sale.inputs[0].sighash_type.expect("sale sighash").to_u32(),
        u32::from(LISTING_SALE_SIGHASH_U8)
    );
    assert_eq!(sale.inputs[0].tap_scripts.len(), 1);
    let (_control_block, (script, leaf_version)) =
        sale.inputs[0].tap_scripts.iter().next().expect("tap leaf");
    assert_eq!(
        script.to_hex_string(),
        format!("20{SELLER_PUBKEY_HEX}ac20{COORDINATOR_PUBKEY_HEX}ba529c")
    );
    assert_eq!(
        *leaf_version,
        bdk_wallet::bitcoin::taproot::LeafVersion::TapScript
    );
    assert_eq!(
        sale.unsigned_tx.output[0].value,
        Amount::from_sat(ASK_SATS + POSTAGE_SATS)
    );
    assert_eq!(
        sale.unsigned_tx.output[0].script_pubkey,
        seller_payout_script()
    );

    let plan = prepare_listing_sale_signature(&created.listing, request.created_at_unix + 1)
        .expect("sale validation");
    assert_eq!(plan.seller_input_index, 0);
    assert_eq!(plan.seller_payout_sats, ASK_SATS + POSTAGE_SATS);
}

#[test]
fn create_listing_builds_recovery_psbt_back_to_seller() {
    let request = sample_create_listing_request();
    let created = create_listing(&request).expect("listing create");
    let (_tx1, _sale, recovery) = decode_listing_psbts(&created.listing);

    assert_eq!(recovery.unsigned_tx.input.len(), 1);
    assert_eq!(recovery.unsigned_tx.output.len(), 1);
    assert_eq!(
        recovery.inputs[0].witness_utxo,
        Some(created.passthrough_txout)
    );
    assert_eq!(
        recovery.unsigned_tx.output[0].script_pubkey,
        request.recovery_script_pubkey
    );
    assert_eq!(
        recovery.unsigned_tx.output[0].value,
        Amount::from_sat(POSTAGE_SATS)
    );
    assert!(
        recovery.inputs[0].sighash_type.is_none(),
        "recovery should use default full-transaction signing"
    );
}

#[test]
fn create_listing_rejects_invalid_request_values() {
    let mut request = sample_create_listing_request();
    request.ask_sats = 0;
    let err = create_listing(&request).expect_err("zero ask rejected");
    assert!(err.to_string().contains("ask_sats must be > 0"));

    let mut request = sample_create_listing_request();
    request.seller_prevout.value = Amount::from_sat(0);
    let err = create_listing(&request).expect_err("zero postage rejected");
    assert!(err.to_string().contains("seller prevout value must be > 0"));

    let mut request = sample_create_listing_request();
    request.expires_at_unix = request.created_at_unix;
    let err = create_listing(&request).expect_err("bad expiry rejected");
    assert!(err.to_string().contains("expiration must be greater"));
}

#[test]
fn sign_listing_sale_psbt_adds_valid_seller_script_path_signature() {
    let request = sample_create_listing_request();
    let created = create_listing(&request).expect("listing create");

    let signed_base64 = sign_listing_sale_psbt(
        &created.listing,
        SELLER_SECRET_KEY_HEX,
        request.created_at_unix + 1,
    )
    .expect("seller sale signing");
    let signed = decode_psbt(&signed_base64);

    assert_eq!(signed.inputs[0].tap_script_sigs.len(), 1);
    assert!(signed.inputs[0].tap_key_sig.is_none());
    assert!(signed.inputs[0].final_script_witness.is_none());

    let ((pubkey, leaf_hash), signature) = signed.inputs[0]
        .tap_script_sigs
        .iter()
        .next()
        .expect("seller script signature");
    assert_eq!(pubkey.to_string(), SELLER_PUBKEY_HEX);
    assert_eq!(
        signature.sighash_type,
        TapSighashType::SinglePlusAnyoneCanPay
    );

    let (_control_block, (script, leaf_version)) = signed.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    assert_eq!(*leaf_hash, TapLeafHash::from_script(script, *leaf_version));

    let prevouts: Vec<TxOut> = signed
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();
    let sighash = SighashCache::new(&signed.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            *leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");
    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature.signature, &message, pubkey)
        .expect("signature verifies");
}

#[test]
fn sign_listing_sale_psbt_rejects_wrong_seller_key() {
    let request = sample_create_listing_request();
    let created = create_listing(&request).expect("listing create");

    let err = sign_listing_sale_psbt(
        &created.listing,
        WRONG_SELLER_SECRET_KEY_HEX,
        request.created_at_unix + 1,
    )
    .expect_err("wrong seller key rejected");

    assert!(err.to_string().contains("does not match listing seller"));
}

#[test]
fn sign_listing_sale_psbt_rejects_mutated_sale_shape() {
    let request = sample_create_listing_request();
    let mut listing = create_listing(&request).expect("listing create").listing;
    let mut sale = decode_psbt(&listing.sale_psbt_base64);
    sale.unsigned_tx.output[0].value = Amount::from_sat(ASK_SATS + POSTAGE_SATS - 1);
    listing.sale_psbt_base64 = encode_psbt(&sale);

    let err = sign_listing_sale_psbt(&listing, SELLER_SECRET_KEY_HEX, request.created_at_unix + 1)
        .expect_err("mutated sale rejected");

    assert!(err.to_string().contains("seller payout output"));
}

#[test]
fn sign_listing_sale_psbt_rejects_missing_tap_leaf_metadata() {
    let request = sample_create_listing_request();
    let mut listing = create_listing(&request).expect("listing create").listing;
    let mut sale = decode_psbt(&listing.sale_psbt_base64);
    sale.inputs[0].tap_scripts.clear();
    listing.sale_psbt_base64 = encode_psbt(&sale);

    let err = sign_listing_sale_psbt(&listing, SELLER_SECRET_KEY_HEX, request.created_at_unix + 1)
        .expect_err("missing tap leaf rejected");

    assert!(err.to_string().contains("missing passthrough tap leaf"));
}

fn signed_sale_listing() -> (CreateListingRequest, ListingEnvelopeV1) {
    let request = sample_create_listing_request();
    let mut listing = create_listing(&request).expect("listing create").listing;
    listing.sale_psbt_base64 =
        sign_listing_sale_psbt(&listing, SELLER_SECRET_KEY_HEX, request.created_at_unix + 1)
            .expect("seller sale signature");
    (request, listing)
}

fn buyer_funding_input(value_sats: u64) -> ListingBuyerFundingInput {
    ListingBuyerFundingInput {
        previous_output: OutPoint::new(sample_txid(0x44), 1),
        witness_utxo: TxOut {
            value: Amount::from_sat(value_sats),
            script_pubkey: buyer_receive_script(),
        },
    }
}

#[test]
fn finalize_listing_purchase_builds_buyer_funded_psbt_preserving_seller_signature() {
    let (request, listing) = signed_sale_listing();
    let buyer_input_value = ASK_SATS + POSTAGE_SATS + 5_000 + 250;

    let finalized = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(buyer_input_value)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: Some(seller_payout_script()),
        change_sats: 5_000,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect("buyer finalization");
    let psbt = decode_psbt(&finalized.psbt_base64);

    assert_eq!(finalized.fee_sats, 250);
    assert_eq!(finalized.seller_input_index, 0);
    assert_eq!(finalized.buyer_receive_output_index, 1);
    assert_eq!(finalized.change_output_index, Some(2));
    assert_eq!(psbt.unsigned_tx.input.len(), 2);
    assert_eq!(psbt.inputs.len(), 2);
    assert_eq!(psbt.unsigned_tx.output.len(), 3);
    assert_eq!(psbt.outputs.len(), 3);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_sat(ASK_SATS + POSTAGE_SATS)
    );
    assert_eq!(
        psbt.unsigned_tx.output[0].script_pubkey,
        seller_payout_script()
    );
    assert_eq!(
        psbt.unsigned_tx.output[1].value,
        Amount::from_sat(POSTAGE_SATS)
    );
    assert_eq!(
        psbt.unsigned_tx.output[1].script_pubkey,
        buyer_receive_script()
    );
    assert_eq!(psbt.unsigned_tx.output[2].value, Amount::from_sat(5_000));
    assert_eq!(
        psbt.inputs[1]
            .witness_utxo
            .as_ref()
            .expect("buyer prevout")
            .value,
        Amount::from_sat(buyer_input_value)
    );

    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    assert!(psbt.inputs[0]
        .tap_script_sigs
        .contains_key(&(seller, leaf_hash)));
    assert_eq!(finalized.listing.sale_psbt_base64, finalized.psbt_base64);
}

#[test]
fn finalized_listing_purchase_can_be_pinned_by_coordinator_default_signature() {
    let (request, listing) = signed_sale_listing();
    let finalized = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect("buyer finalization");

    let coordinator_signed_base64 = sign_listing_coordinator_psbt(
        &finalized.listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 3,
    )
    .expect("coordinator final signing");
    let signed = decode_psbt(&coordinator_signed_base64);

    assert_eq!(signed.inputs[0].tap_script_sigs.len(), 2);
    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    let (_control_block, (script, leaf_version)) = signed.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let coordinator_sig = signed.inputs[0]
        .tap_script_sigs
        .get(&(coordinator, leaf_hash))
        .expect("coordinator sig");
    assert_eq!(coordinator_sig.sighash_type, TapSighashType::Default);

    let prevouts: Vec<TxOut> = signed
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();
    let sighash = SighashCache::new(&signed.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("sighash");
    let message = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_schnorr(&coordinator_sig.signature, &message, &coordinator)
        .expect("coordinator signature verifies");
}

#[test]
fn finalize_listing_purchase_rejects_missing_seller_signature() {
    let request = sample_create_listing_request();
    let listing = create_listing(&request).expect("listing create").listing;

    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("unsigned listing rejected");

    assert!(err.to_string().contains("missing seller sale signature"));
}

#[test]
fn finalize_listing_purchase_rejects_duplicate_passthrough_buyer_input() {
    let (request, listing) = signed_sale_listing();
    let passthrough_outpoint = listing
        .passthrough_outpoint
        .parse::<OutPoint>()
        .expect("passthrough outpoint");

    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![ListingBuyerFundingInput {
            previous_output: passthrough_outpoint,
            witness_utxo: TxOut {
                value: Amount::from_sat(ASK_SATS + POSTAGE_SATS + 500),
                script_pubkey: buyer_receive_script(),
            },
        }],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("duplicate passthrough rejected");

    assert!(err.to_string().contains("duplicates passthrough outpoint"));
}

#[test]
fn finalize_listing_purchase_rejects_insufficient_funding_and_zero_fee() {
    let (request, listing) = signed_sale_listing();
    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing: listing.clone(),
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS - 1)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("insufficient funding rejected");
    assert!(err.to_string().contains("buyer funding is insufficient"));

    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("zero fee rejected");
    assert!(err.to_string().contains("fee must be > 0"));
}

#[test]
fn finalize_listing_purchase_rejects_missing_receive_or_change_script() {
    let (request, listing) = signed_sale_listing();
    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing: listing.clone(),
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: ScriptBuf::new(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("empty receive script rejected");
    assert!(err.to_string().contains("buyer receive scriptPubKey"));

    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 1,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect_err("missing change script rejected");
    assert!(err.to_string().contains("change scriptPubKey"));
}

#[test]
fn finalize_listing_purchase_rejects_already_coordinator_signed_psbt() {
    let (request, mut listing) = signed_sale_listing();
    listing.sale_psbt_base64 = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 2,
    )
    .expect("coordinator signing");

    let err = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 3,
    })
    .expect_err("already coordinator signed rejected");

    assert!(err.to_string().contains("already coordinator signed"));
}

#[test]
fn wallet_create_listing_purchase_funds_and_signs_buyer_inputs_only() {
    let (request, listing) = signed_sale_listing();
    let mut wallet = funded_unified_wallet(true);
    let buyer_receive_script = wallet
        .vault_wallet
        .peek_address(bdk_wallet::KeychainKind::External, 0)
        .script_pubkey();

    let purchase = wallet
        .create_listing_purchase(&CreateListingPurchaseRequest {
            listing,
            now_unix: request.created_at_unix + 2,
        })
        .expect("listing purchase");
    let psbt = decode_psbt(&purchase.psbt_base64);

    assert_eq!(purchase.seller_input_index, 0);
    assert_eq!(purchase.buyer_receive_output_index, 1);
    assert!(purchase.buyer_input_count > 0);
    assert!(purchase.fee_sats > 0);
    assert_eq!(purchase.listing.sale_psbt_base64, purchase.psbt_base64);
    assert_eq!(
        psbt.unsigned_tx.input[0].previous_output.to_string(),
        purchase.listing.passthrough_outpoint
    );
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_sat(ASK_SATS + POSTAGE_SATS)
    );
    assert_eq!(
        psbt.unsigned_tx.output[0].script_pubkey,
        seller_payout_script()
    );
    assert_eq!(
        psbt.unsigned_tx.output[1].value,
        Amount::from_sat(POSTAGE_SATS)
    );
    assert_eq!(
        psbt.unsigned_tx.output[1].script_pubkey,
        buyer_receive_script
    );

    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let seller_sig = psbt.inputs[0]
        .tap_script_sigs
        .get(&(seller, leaf_hash))
        .expect("seller sig");
    assert_eq!(
        seller_sig.sighash_type,
        TapSighashType::SinglePlusAnyoneCanPay
    );
    assert!(psbt.inputs[0].final_script_witness.is_none());

    for index in 1..psbt.inputs.len() {
        assert!(
            input_has_signature(&psbt.inputs[index]),
            "buyer input {index} must be signed"
        );
    }
}

#[test]
fn wallet_created_listing_purchase_can_be_coordinator_pinned() {
    let (request, listing) = signed_sale_listing();
    let mut wallet = funded_unified_wallet(true);
    let purchase = wallet
        .create_listing_purchase(&CreateListingPurchaseRequest {
            listing,
            now_unix: request.created_at_unix + 2,
        })
        .expect("listing purchase");

    let coordinator_signed_base64 = sign_listing_coordinator_psbt(
        &purchase.listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 3,
    )
    .expect("coordinator signing");
    let psbt = decode_psbt(&coordinator_signed_base64);

    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    assert_eq!(
        psbt.inputs[0]
            .tap_script_sigs
            .get(&(coordinator, leaf_hash))
            .expect("coordinator sig")
            .sighash_type,
        TapSighashType::Default
    );
}

#[test]
fn finalize_listing_sale_builds_passthrough_witness_and_extracts_tx() {
    let (request, listing) = signed_sale_listing();
    let finalized = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(ASK_SATS + POSTAGE_SATS + 500)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect("buyer finalization");
    let mut listing = finalized.listing;
    let mut sale_psbt = decode_psbt(&listing.sale_psbt_base64);
    sale_psbt.inputs[1].final_script_witness = Some(Witness::from_slice(&[b"buyer-sig".to_vec()]));
    listing.sale_psbt_base64 = encode_psbt(&sale_psbt);
    listing.sale_psbt_base64 = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 3,
    )
    .expect("coordinator signing");

    let result =
        finalize_listing_sale(&listing, request.created_at_unix + 4).expect("sale finalization");
    let finalized_psbt = decode_psbt(&result.finalized_psbt_base64);
    let extracted_tx = finalized_psbt.clone().extract_tx().expect("extract tx");
    let witness = finalized_psbt.inputs[0]
        .final_script_witness
        .as_ref()
        .expect("passthrough witness");

    assert_eq!(result.seller_input_index, 0);
    assert_eq!(result.passthrough_witness_items, 4);
    assert_eq!(witness.len(), 4);
    assert_eq!(witness.nth(0).expect("coordinator sig").len(), 64);
    let seller_sig = witness.nth(1).expect("seller sig");
    assert_eq!(seller_sig.len(), 65);
    assert_eq!(
        seller_sig.last().copied(),
        Some(LISTING_SALE_SIGHASH_U8),
        "seller signature must retain SIGHASH_SINGLE|ANYONECANPAY byte"
    );
    assert_eq!(
        hex::encode(witness.nth(2).expect("script")),
        format!("20{SELLER_PUBKEY_HEX}ac20{COORDINATOR_PUBKEY_HEX}ba529c")
    );
    assert_eq!(extracted_tx.input[0].witness, *witness);
    assert_eq!(result.txid, extracted_tx.compute_txid().to_string());
    assert_eq!(
        result.tx_hex,
        hex::encode(bdk_wallet::bitcoin::consensus::serialize(&extracted_tx))
    );
}

#[test]
fn finalize_listing_sale_rejects_missing_coordinator_signature() {
    let (request, listing) = signed_sale_listing();

    let err = finalize_listing_sale(&listing, request.created_at_unix + 2)
        .expect_err("missing coordinator signature rejected");

    assert!(err.to_string().contains("missing coordinator signature"));
}

#[test]
fn full_wallet_listing_purchase_flow_reaches_broadcast_transaction() {
    let request = sample_create_listing_request();
    let mut listing = create_listing(&request).expect("listing create").listing;
    listing.sale_psbt_base64 =
        sign_listing_sale_psbt(&listing, SELLER_SECRET_KEY_HEX, request.created_at_unix + 1)
            .expect("seller signing");

    let mut wallet = funded_unified_wallet(true);
    let purchase = wallet
        .create_listing_purchase(&CreateListingPurchaseRequest {
            listing,
            now_unix: request.created_at_unix + 2,
        })
        .expect("wallet purchase");
    let mut listing = purchase.listing;
    listing.sale_psbt_base64 = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 3,
    )
    .expect("coordinator signing");

    let finalized =
        finalize_listing_sale(&listing, request.created_at_unix + 4).expect("sale finalization");
    let psbt = decode_psbt(&finalized.finalized_psbt_base64);
    let tx = psbt.extract_tx().expect("extract tx");

    assert_eq!(finalized.seller_input_index, 0);
    assert_eq!(finalized.passthrough_witness_items, 4);
    assert_eq!(finalized.txid, tx.compute_txid().to_string());
    assert_eq!(
        tx.output[0].value,
        Amount::from_sat(request.ask_sats + POSTAGE_SATS)
    );
    assert_eq!(tx.output[0].script_pubkey, seller_payout_script());
    assert_eq!(tx.output[1].value, Amount::from_sat(POSTAGE_SATS));
    for input in &tx.input {
        assert!(!input.witness.is_empty(), "every input must be finalized");
    }
}

#[test]
fn wallet_create_listing_purchase_requires_verified_ordinals_state() {
    let (request, listing) = signed_sale_listing();
    let mut wallet = funded_unified_wallet(false);

    let err = wallet
        .create_listing_purchase(&CreateListingPurchaseRequest {
            listing,
            now_unix: request.created_at_unix + 2,
        })
        .expect_err("ordinals safety lock rejected");

    assert!(err.to_string().to_ascii_lowercase().contains("safety lock"));
}

#[test]
fn sign_listing_coordinator_psbt_adds_default_signature_and_preserves_seller_sig() {
    let (request, listing) = signed_sale_listing();

    let signed_base64 = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 2,
    )
    .expect("coordinator signing");
    let signed = decode_psbt(&signed_base64);

    assert_eq!(signed.inputs[0].tap_script_sigs.len(), 2);
    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    let (_control_block, (script, leaf_version)) = signed.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let seller_sig = signed.inputs[0]
        .tap_script_sigs
        .get(&(seller, leaf_hash))
        .expect("seller sig");
    let coordinator_sig = signed.inputs[0]
        .tap_script_sigs
        .get(&(coordinator, leaf_hash))
        .expect("coordinator sig");

    assert_eq!(
        seller_sig.sighash_type,
        TapSighashType::SinglePlusAnyoneCanPay
    );
    assert_eq!(coordinator_sig.sighash_type, TapSighashType::Default);

    let prevouts: Vec<TxOut> = signed
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();
    let sighash = SighashCache::new(&signed.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("sighash");
    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&coordinator_sig.signature, &message, &coordinator)
        .expect("coordinator signature verifies");
}

#[test]
fn sign_listing_coordinator_psbt_rejects_wrong_coordinator_key() {
    let (request, listing) = signed_sale_listing();

    let err = sign_listing_coordinator_psbt(
        &listing,
        WRONG_COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 2,
    )
    .expect_err("wrong coordinator key rejected");

    assert!(err
        .to_string()
        .contains("does not match listing coordinator"));
}

#[test]
fn sign_listing_coordinator_psbt_rejects_missing_seller_signature() {
    let request = sample_create_listing_request();
    let listing = create_listing(&request).expect("listing create").listing;

    let err = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 2,
    )
    .expect_err("missing seller signature rejected");

    assert!(err.to_string().contains("missing seller sale signature"));
}

#[test]
fn coordinator_default_signature_fails_after_final_tx_mutation() {
    let (request, listing) = signed_sale_listing();
    let signed_base64 = sign_listing_coordinator_psbt(
        &listing,
        COORDINATOR_SECRET_KEY_HEX,
        request.created_at_unix + 2,
    )
    .expect("coordinator signing");
    let mut signed = decode_psbt(&signed_base64);

    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");
    let (_control_block, (script, leaf_version)) = signed.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let coordinator_sig = *signed.inputs[0]
        .tap_script_sigs
        .get(&(coordinator, leaf_hash))
        .expect("coordinator sig");

    signed.unsigned_tx.output[0].value = Amount::from_sat(ASK_SATS + POSTAGE_SATS - 1);

    let prevouts: Vec<TxOut> = signed
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();
    let sighash = SighashCache::new(&signed.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("sighash");
    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    assert!(
        secp.verify_schnorr(&coordinator_sig.signature, &message, &coordinator)
            .is_err(),
        "coordinator SIGHASH_DEFAULT signature must pin the final transaction"
    );
}

#[test]
fn passthrough_tapscript_is_ord_style_two_of_two_checksigadd() {
    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let coordinator = XOnlyPublicKey::from_str(COORDINATOR_PUBKEY_HEX).expect("coordinator pubkey");

    let script = passthrough_tapscript(seller, coordinator);

    assert_eq!(
        script.to_hex_string(),
        format!("20{SELLER_PUBKEY_HEX}ac20{COORDINATOR_PUBKEY_HEX}ba529c")
    );
}

#[test]
fn listing_envelope_hashes_and_validates_deterministically() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let id_a = listing.listing_id_hex().expect("listing id");
    let id_b = listing.listing_id_hex().expect("listing id stable");

    assert_eq!(id_a, id_b);
    assert_eq!(id_a.len(), 64);
}

#[test]
fn prepare_listing_sale_signature_accepts_exact_sale_shape() {
    let passthrough_outpoint = OutPoint::new(sample_txid(0x22), 0);
    let psbt = sale_psbt_base64(
        passthrough_outpoint,
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let plan =
        prepare_listing_sale_signature(&listing, 1_800_000_001).expect("valid sale signing plan");

    assert_eq!(plan.seller_input_index, 0);
    assert_eq!(plan.sighash_u8, LISTING_SALE_SIGHASH_U8);
    assert_eq!(plan.seller_payout_sats, ASK_SATS + POSTAGE_SATS);
}

#[test]
fn prepare_listing_sale_signature_rejects_wrong_sighash() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(0x01),
        false,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("wrong sighash rejected");

    assert!(err
        .to_string()
        .contains("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY"));
}

#[test]
fn prepare_listing_sale_signature_rejects_missing_sighash() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        None,
        false,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("missing sighash rejected");

    assert!(err
        .to_string()
        .contains("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY"));
}

#[test]
fn prepare_listing_sale_signature_rejects_mutated_seller_payout() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS - 1,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let err =
        prepare_listing_sale_signature(&listing, 1_800_000_001).expect_err("short payout rejected");

    assert!(err.to_string().contains("seller payout output"));
}

#[test]
fn prepare_listing_sale_signature_rejects_missing_single_output() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let mut psbt = decode_psbt(&psbt);
    psbt.unsigned_tx.output.clear();
    psbt.outputs.clear();
    let listing = sample_listing(encode_psbt(&psbt));

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("missing SINGLE output rejected");

    assert!(err.to_string().contains("missing seller payout output"));
}

#[test]
fn prepare_listing_sale_signature_rejects_wrong_passthrough_outpoint() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x33), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("wrong passthrough input rejected");

    assert!(err.to_string().contains("contains no passthrough input"));
}

#[test]
fn prepare_listing_sale_signature_rejects_duplicate_passthrough_inputs() {
    let passthrough_outpoint = OutPoint::new(sample_txid(0x22), 0);
    let psbt = sale_psbt_base64(
        passthrough_outpoint,
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let mut psbt = decode_psbt(&psbt);
    psbt.unsigned_tx.input.push(TxIn {
        previous_output: passthrough_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    psbt.inputs.push(psbt.inputs[0].clone());
    let listing = sample_listing(encode_psbt(&psbt));

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("duplicate passthrough inputs rejected");

    assert!(err.to_string().contains("contains 2 passthrough inputs"));
}

#[test]
fn prepare_listing_sale_signature_rejects_postage_mismatch() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let mut psbt = decode_psbt(&psbt);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(POSTAGE_SATS + 1),
        script_pubkey: ScriptBuf::new(),
    });
    let listing = sample_listing(encode_psbt(&psbt));

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("postage mismatch rejected");

    assert!(err.to_string().contains("passthrough input postage"));
}

#[test]
fn prepare_listing_sale_signature_rejects_wrong_payout_script() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        ScriptBuf::new(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("wrong payout script rejected");

    assert!(err.to_string().contains("seller payout script"));
}

#[test]
fn prepare_listing_sale_signature_rejects_signed_seller_input() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        true,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_000_001)
        .expect_err("already signed seller input rejected");

    assert!(err.to_string().contains("must be unsigned"));
}

#[test]
fn prepare_listing_sale_signature_rejects_expired_listing() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );
    let listing = sample_listing(psbt);

    let err = prepare_listing_sale_signature(&listing, 1_800_003_600)
        .expect_err("expired listing rejected");

    assert!(err.to_string().contains("listing has expired"));
}

#[test]
fn listing_envelope_rejects_malformed_pubkeys_and_expiration() {
    let psbt = sale_psbt_base64(
        OutPoint::new(sample_txid(0x22), 0),
        ASK_SATS + POSTAGE_SATS,
        seller_payout_script(),
        Some(LISTING_SALE_SIGHASH_U8),
        false,
    );

    let mut listing = sample_listing(psbt.clone());
    listing.seller_pubkey_hex = "not-a-pubkey".to_string();
    let err = listing.listing_id_hex().expect_err("bad pubkey rejected");
    assert!(err.to_string().contains("invalid seller pubkey"));

    let mut listing = sample_listing(psbt);
    listing.expires_at_unix = listing.created_at_unix;
    let err = listing
        .listing_id_hex()
        .expect_err("non-increasing expiration rejected");
    assert!(err.to_string().contains("expiration must be greater"));
}

#[test]
fn test_input_and_output_shift_maintains_valid_signature_and_secures_payout() {
    // Tests that an attacker CAN shift the seller's input/output to a different index
    // because Taproot SIGHASH_SINGLE|ANYONECANPAY does not commit to the input index.
    // However, the output at that new index MUST perfectly match the seller's payout.
    let (_request, listing) = signed_sale_listing();
    let mut psbt = decode_psbt(&listing.sale_psbt_base64);

    // Shift seller input and output to index 1
    let dummy_input = TxIn {
        previous_output: OutPoint::new(sample_txid(0x99), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let dummy_output = TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new(),
    };

    psbt.unsigned_tx.input.insert(0, dummy_input);
    psbt.unsigned_tx.output.insert(0, dummy_output);

    let mut dummy_psbt_input = bdk_wallet::bitcoin::psbt::Input::default();
    dummy_psbt_input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new(),
    });
    psbt.inputs.insert(0, dummy_psbt_input);
    psbt.outputs
        .insert(0, bdk_wallet::bitcoin::psbt::Output::default());

    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[1]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let seller_sig = psbt.inputs[1]
        .tap_script_sigs
        .get(&(seller, leaf_hash))
        .expect("seller sig");

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();

    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            1,                               // Verify for index 1
            &Prevouts::One(1, &prevouts[1]), // ANYONECANPAY
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");

    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    assert!(
        secp.verify_schnorr(&seller_sig.signature, &message, &seller)
            .is_ok(),
        "Seller signature must REMAIN VALID if input/output index is shifted but output is intact"
    );

    // BUT, if the attacker mutates the output at that new index, the signature MUST break.
    psbt.unsigned_tx.output[1].value = Amount::from_sat(ASK_SATS + POSTAGE_SATS - 1);
    let mutated_sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            1,
            &Prevouts::One(1, &prevouts[1]),
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");
    let mutated_message = Message::from_digest(mutated_sighash.to_byte_array());
    assert!(
        secp.verify_schnorr(&seller_sig.signature, &mutated_message, &seller)
            .is_err(),
        "Seller signature must BECOME INVALID if output amount is mutated"
    );
}

#[test]
fn test_prevent_replay_attack_on_different_utxo() {
    // Tests that the seller's signature cannot be replayed on a different passthrough UTXO.
    let (_request, listing) = signed_sale_listing();
    let mut psbt = decode_psbt(&listing.sale_psbt_base64);

    // Attacker tries to replay the signature on a different UTXO
    psbt.unsigned_tx.input[0].previous_output = OutPoint::new(sample_txid(0x88), 0);
    // Even if they keep the same value/script in witness_utxo, the signature commits to the prevout TXID/VOUT.

    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let seller_sig = psbt.inputs[0]
        .tap_script_sigs
        .get(&(seller, leaf_hash))
        .expect("seller sig");

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();

    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::One(0, &prevouts[0]), // ANYONECANPAY
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");

    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    assert!(
        secp.verify_schnorr(&seller_sig.signature, &message, &seller)
            .is_err(),
        "Seller signature must be tied to the specific passthrough outpoint"
    );
}

#[test]
fn test_prevent_payout_script_substitution_attack() {
    // Tests that the seller's SIGHASH_SINGLE signature commits to the payout script,
    // so an attacker cannot redirect funds to a different address.
    let (_request, listing) = signed_sale_listing();
    let mut psbt = decode_psbt(&listing.sale_psbt_base64);

    let seller = XOnlyPublicKey::from_str(SELLER_PUBKEY_HEX).expect("seller pubkey");
    let (_control_block, (script, leaf_version)) = psbt.inputs[0]
        .tap_scripts
        .iter()
        .next()
        .expect("tap script");
    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
    let seller_sig = psbt.inputs[0]
        .tap_script_sigs
        .get(&(seller, leaf_hash))
        .expect("seller sig");

    // First verify the original signature is valid
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("witness utxo"))
        .collect();
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::One(0, &prevouts[0]),
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");
    let message = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    assert!(
        secp.verify_schnorr(&seller_sig.signature, &message, &seller)
            .is_ok(),
        "Original signature must be valid"
    );

    // Now substitute the payout script with an attacker's script
    let attacker_script =
        ScriptBuf::from_hex("5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
            .expect("attacker script");
    psbt.unsigned_tx.output[0].script_pubkey = attacker_script;

    let mutated_sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::One(0, &prevouts[0]),
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("sighash");
    let mutated_message = Message::from_digest(mutated_sighash.to_byte_array());
    assert!(
        secp.verify_schnorr(&seller_sig.signature, &mutated_message, &seller)
            .is_err(),
        "Seller signature must BECOME INVALID if payout script is substituted"
    );
}

#[test]
fn finalize_listing_purchase_adds_cpfp_anchor_output_when_requested() {
    let (request, listing) = signed_sale_listing();
    let anchor_script = buyer_receive_script(); // Buyer-controlled script for CPFP spending
    let anchor_sats = 330u64; // Dust limit anchor
    let buyer_input_value = ASK_SATS + POSTAGE_SATS + anchor_sats + 5_000 + 500;

    let finalized = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(buyer_input_value)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: Some(seller_payout_script()),
        change_sats: 5_000,
        anchor_output: Some(crate::listing::AnchorOutput {
            script_pubkey: anchor_script.clone(),
            value_sats: anchor_sats,
        }),
        now_unix: request.created_at_unix + 2,
    })
    .expect("buyer finalization with anchor");
    let psbt = decode_psbt(&finalized.psbt_base64);

    // Outputs: [0] seller payout, [1] buyer receive, [2] change, [3] anchor
    assert_eq!(psbt.unsigned_tx.output.len(), 4);
    assert_eq!(finalized.anchor_output_index, Some(3));

    let anchor_out = &psbt.unsigned_tx.output[3];
    assert_eq!(anchor_out.value, Amount::from_sat(anchor_sats));
    assert_eq!(anchor_out.script_pubkey, anchor_script);
}

#[test]
fn finalize_listing_purchase_omits_anchor_when_not_requested() {
    let (request, listing) = signed_sale_listing();
    let buyer_input_value = ASK_SATS + POSTAGE_SATS + 500;

    let finalized = finalize_listing_purchase(&FinalizeListingPurchaseRequest {
        listing,
        buyer_inputs: vec![buyer_funding_input(buyer_input_value)],
        buyer_receive_script_pubkey: buyer_receive_script(),
        change_script_pubkey: None,
        change_sats: 0,
        anchor_output: None,
        now_unix: request.created_at_unix + 2,
    })
    .expect("buyer finalization without anchor");
    let psbt = decode_psbt(&finalized.psbt_base64);

    // Outputs: [0] seller payout, [1] buyer receive
    assert_eq!(psbt.unsigned_tx.output.len(), 2);
    assert_eq!(finalized.anchor_output_index, None);
}
