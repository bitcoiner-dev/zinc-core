use crate::offer::OfferEnvelopeV1;
use crate::offer_accept::prepare_offer_acceptance;
use base64::Engine;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::{
    absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

const ASK_SATS: u64 = 100_000;
const SELLER_POSTAGE_SATS: u64 = 330;

/// The accepting wallet's own payout script. Derived locally in production,
/// never read out of the offer envelope.
fn expected_payout_script() -> ScriptBuf {
    ScriptBuf::from_hex("0014000102030405060708090a0b0c0d0e0f1011121314").expect("valid script")
}

/// A script the attacker controls.
fn attacker_payout_script() -> ScriptBuf {
    ScriptBuf::from_hex("0014ffeeddccbbaa99887766554433221100ffeeddcc").expect("valid script")
}

fn sample_seller_txid() -> Txid {
    Txid::from_slice(&[0x11; 32]).expect("valid txid")
}

fn sample_buyer_txid() -> Txid {
    Txid::from_slice(&[0x22; 32]).expect("valid txid")
}

fn build_offer(
    now_unix: i64,
    seller_outpoint: OutPoint,
    psbt_base64: String,
    expires_at_unix: i64,
) -> OfferEnvelopeV1 {
    OfferEnvelopeV1 {
        version: 1,
        seller_pubkey_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .to_string(),
        network: "regtest".to_string(),
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: seller_outpoint.to_string(),
        ask_sats: ASK_SATS,
        fee_rate_sat_vb: 1,
        psbt_base64,
        created_at_unix: now_unix - 10,
        expires_at_unix,
        nonce: 7,
    }
}

fn psbt_base64(
    seller_outpoint: OutPoint,
    include_duplicate_seller_input: bool,
    seller_signed: bool,
    buyer_signed: bool,
) -> String {
    psbt_base64_paying(
        seller_outpoint,
        include_duplicate_seller_input,
        seller_signed,
        buyer_signed,
        expected_payout_script(),
    )
}

fn psbt_base64_paying(
    seller_outpoint: OutPoint,
    include_duplicate_seller_input: bool,
    seller_signed: bool,
    buyer_signed: bool,
    payout_script: ScriptBuf,
) -> String {
    let mut inputs = vec![
        TxIn {
            previous_output: seller_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        },
        TxIn {
            previous_output: OutPoint {
                txid: sample_buyer_txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        },
    ];

    if include_duplicate_seller_input {
        inputs.push(TxIn {
            previous_output: seller_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![
            TxOut {
                value: Amount::from_sat(SELLER_POSTAGE_SATS),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(ASK_SATS + SELLER_POSTAGE_SATS),
                script_pubkey: payout_script,
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(SELLER_POSTAGE_SATS),
        script_pubkey: ScriptBuf::new(),
    });

    if seller_signed {
        let stack = vec![b"seller-sig".to_vec()];
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&stack));
    }
    if buyer_signed {
        let stack = vec![b"buyer-sig".to_vec()];
        psbt.inputs[1].final_script_witness = Some(Witness::from_slice(&stack));
    }

    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

#[test]
fn prepare_offer_acceptance_returns_plan_for_valid_offer() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint, false, false, true);
    let offer = build_offer(now_unix, seller_outpoint, psbt, now_unix + 3600);

    let plan = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect("valid acceptance plan");

    assert_eq!(plan.seller_input_index, 0);
    assert_eq!(plan.input_count, 2);
    assert!(!plan.offer_id.is_empty());
}

#[test]
fn prepare_offer_acceptance_rejects_expired_offer() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint, false, false, true);
    let offer = build_offer(now_unix, seller_outpoint, psbt, now_unix - 1);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("expired offer");
    assert!(err.to_string().contains("offer has expired"));
}

#[test]
fn prepare_offer_acceptance_rejects_missing_seller_input() {
    let now_unix = 1_800_000_000;
    let seller_outpoint_in_offer = OutPoint {
        txid: Txid::from_slice(&[0x33; 32]).expect("txid"),
        vout: 0,
    };
    let seller_outpoint_in_psbt = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint_in_psbt, false, false, true);
    let offer = build_offer(now_unix, seller_outpoint_in_offer, psbt, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("missing seller input");
    assert!(err.to_string().contains("contains no seller input"));
}

#[test]
fn prepare_offer_acceptance_rejects_duplicate_seller_input() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint, true, false, true);
    let offer = build_offer(now_unix, seller_outpoint, psbt, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("duplicate seller inputs");
    assert!(err.to_string().contains("contains 2 seller inputs"));
}

#[test]
fn prepare_offer_acceptance_rejects_signed_seller_input() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint, false, true, true);
    let offer = build_offer(now_unix, seller_outpoint, psbt, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("signed seller input");
    assert!(err.to_string().contains("seller input"));
    assert!(err.to_string().contains("must be unsigned"));
}

#[test]
fn prepare_offer_acceptance_rejects_unsigned_buyer_input() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let psbt = psbt_base64(seller_outpoint, false, false, false);
    let offer = build_offer(now_unix, seller_outpoint, psbt, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("unsigned buyer input");
    assert!(err.to_string().contains("buyer input"));
    assert!(err.to_string().contains("must be signed"));
}

#[test]
fn prepare_offer_acceptance_rejects_seller_input_not_first() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let mut psbt = {
        let encoded = psbt_base64(seller_outpoint, false, false, true);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .expect("base64");
        Psbt::deserialize(&bytes).expect("psbt")
    };

    psbt.unsigned_tx.input.swap(0, 1);
    psbt.inputs.swap(0, 1);

    let encoded = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    let offer = build_offer(now_unix, seller_outpoint, encoded, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("seller input must be first");
    assert!(err.to_string().contains("must be first input"));
}

/// A hostile counterparty crafts an offer whose amounts validate perfectly but
/// whose payout output pays an address they control. The value checks are
/// self-consistent because `ask_sats` comes from the attacker's own envelope, so
/// only the script binding catches this — without it the seller signs their
/// inscription away for nothing.
#[test]
fn prepare_offer_acceptance_rejects_payout_to_a_foreign_script() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };

    let encoded = psbt_base64_paying(
        seller_outpoint,
        false,
        false,
        true,
        attacker_payout_script(),
    );
    let offer = build_offer(now_unix, seller_outpoint, encoded, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("a payout to a foreign script must be rejected");
    assert!(
        err.to_string()
            .contains("does not pay this wallet's payout script"),
        "unexpected error: {err}"
    );
}

/// The expectation must come from the local wallet. An empty script would let
/// a caller accidentally opt out of the binding entirely.
#[test]
fn prepare_offer_acceptance_rejects_empty_expected_payout_script() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let encoded = psbt_base64(seller_outpoint, false, false, true);
    let offer = build_offer(now_unix, seller_outpoint, encoded, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, ScriptBuf::new().as_script())
        .expect_err("an empty expectation must be rejected");
    assert!(
        err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn prepare_offer_acceptance_rejects_non_ord_output_layout() {
    let now_unix = 1_800_000_000;
    let seller_outpoint = OutPoint {
        txid: sample_seller_txid(),
        vout: 0,
    };
    let mut psbt = {
        let encoded = psbt_base64(seller_outpoint, false, false, true);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .expect("base64");
        Psbt::deserialize(&bytes).expect("psbt")
    };

    psbt.unsigned_tx.output.swap(0, 1);
    psbt.outputs.swap(0, 1);

    let encoded = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    let offer = build_offer(now_unix, seller_outpoint, encoded, now_unix + 3600);

    let err = prepare_offer_acceptance(&offer, now_unix, expected_payout_script().as_script())
        .expect_err("must reject non-canonical outputs");
    assert!(err
        .to_string()
        .contains("buyer postage output must be first"));
}
