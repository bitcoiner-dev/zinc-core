use crate::builder::{AddressScheme, Seed64, WalletBuilder};
use crate::offer_accept::prepare_offer_acceptance;
use crate::offer_create::CreateOfferRequest;
use base64::Engine;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::ConfirmationBlockTime;
use bdk_wallet::KeychainKind;
use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[31] = uid;
    let dummy_txid = Txid::from_byte_array(hash_bytes);

    let dummy_input = bdk_wallet::bitcoin::TxIn {
        previous_output: OutPoint::new(dummy_txid, 0),
        script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
        sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: bdk_wallet::bitcoin::Witness::default(),
    };

    Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![dummy_input],
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
        .reveal_next_address(KeychainKind::External)
        .address
        .script_pubkey();

    let tx = create_dummy_tx(200_000, receive_script, 19);
    let mut graph = bdk_wallet::chain::TxGraph::default();
    let dummy_block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();
    let _ = graph.insert_tx(tx.clone());
    let _ = graph.insert_anchor(
        tx.compute_txid(),
        ConfirmationBlockTime {
            block_id: bdk_wallet::chain::BlockId {
                height: 101,
                hash: dummy_block_hash,
            },
            confirmation_time: 1001,
        },
    );

    let mut last_active = BTreeMap::new();
    last_active.insert(KeychainKind::External, 5);
    let update = bdk_wallet::Update {
        tx_update: graph.into(),
        chain: Default::default(),
        last_active_indices: last_active,
    };
    wallet
        .vault_wallet
        .apply_update(update)
        .expect("apply update");

    wallet
}

fn sample_request(wallet: &crate::ZincWallet) -> CreateOfferRequest {
    let seller_seed = [9u8; 64];
    let mut seller_wallet =
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seller_seed))
            .with_scheme(AddressScheme::Unified)
            .build()
            .expect("seller wallet build");
    let seller_input_address = seller_wallet
        .next_taproot_address()
        .expect("seller address")
        .to_string();

    let seller_txid =
        Txid::from_str("6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799")
            .expect("txid");
    CreateOfferRequest {
        inscription_id: "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
            .to_string(),
        seller_outpoint: OutPoint::new(seller_txid, 0),
        seller_input_address: seller_input_address.clone(),
        seller_payout_address: wallet
            .peek_payment_address(0)
            .expect("main payment address")
            .to_string(),
        seller_output_value_sats: 330,
        ask_sats: 1_000,
        fee_rate_sat_vb: 1,
        created_at_unix: 1_710_000_000,
        expires_at_unix: 1_710_003_600,
        nonce: 42,
        publisher_pubkey_hex: None,
    }
}

fn input_has_signature(input: &bdk_wallet::bitcoin::psbt::Input) -> bool {
    input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
}

#[test]
fn create_offer_builds_ord_compatible_psbt_and_offer_envelope() {
    let mut wallet = funded_unified_wallet(true);
    let request = sample_request(&wallet);

    let created = wallet.create_offer(&request).expect("offer create");

    assert_eq!(created.inscription, request.inscription_id);
    assert_eq!(created.offer.inscription_id, request.inscription_id);
    assert_eq!(
        created.offer.seller_outpoint,
        request.seller_outpoint.to_string()
    );
    assert_eq!(created.offer.ask_sats, request.ask_sats);
    assert_eq!(created.psbt, created.offer.psbt_base64);
    assert_eq!(created.seller_address, request.seller_payout_address);

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(created.psbt.as_bytes())
        .expect("base64");
    let psbt = Psbt::deserialize(&psbt_bytes).expect("psbt decode");

    let seller_input_index = psbt
        .unsigned_tx
        .input
        .iter()
        .position(|txin| txin.previous_output == request.seller_outpoint)
        .expect("seller input present");
    assert!(psbt.inputs.len() > 1, "expected buyer + seller inputs");

    let seller_input = &psbt.inputs[seller_input_index];
    assert!(
        !input_has_signature(seller_input),
        "seller input must remain unsigned"
    );

    for (index, input) in psbt.inputs.iter().enumerate() {
        if index == seller_input_index {
            continue;
        }
        assert!(
            input_has_signature(input),
            "buyer input {index} must be signed"
        );
    }

    let plan = prepare_offer_acceptance(&created.offer, request.created_at_unix + 1)
        .expect("acceptance plan");
    assert_eq!(plan.seller_input_index, seller_input_index);
}

#[test]
fn create_offer_requires_verified_ordinals_state() {
    let mut wallet = funded_unified_wallet(false);
    let request = sample_request(&wallet);

    let err = wallet.create_offer(&request).expect_err("must fail");
    assert!(
        err.to_string().to_ascii_lowercase().contains("safety lock"),
        "unexpected error: {err}"
    );
}

#[test]
fn create_offer_rejects_non_increasing_expiration() {
    let mut wallet = funded_unified_wallet(true);
    let mut request = sample_request(&wallet);
    request.expires_at_unix = request.created_at_unix;

    let err = wallet.create_offer(&request).expect_err("must fail");
    assert!(
        err.to_string().contains("expiration must be greater"),
        "unexpected error: {err}"
    );
}

#[test]
fn create_offer_preserves_ord_input_and_output_ordering() {
    // ord constructs offer tx templates with:
    // 1) seller inscription input first
    // 2) buyer postage output first
    // 3) seller payout output second
    //
    // Build multiple offers to ensure ordering is stable and never randomized.
    for _ in 0..8 {
        let mut wallet = funded_unified_wallet(true);
        let request = sample_request(&wallet);

        let buyer_receive_script = wallet
            .vault_wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .script_pubkey();
        let expected_change_script = wallet
            .vault_wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .script_pubkey();
        let seller_script = request
            .seller_payout_address
            .parse::<bdk_wallet::bitcoin::Address<bdk_wallet::bitcoin::address::NetworkUnchecked>>()
            .expect("seller address parse")
            .require_network(Network::Regtest)
            .expect("seller address network")
            .script_pubkey();

        let created = wallet.create_offer(&request).expect("offer create");
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(created.psbt.as_bytes())
            .expect("base64");
        let psbt = Psbt::deserialize(&psbt_bytes).expect("psbt decode");

        assert!(
            psbt.unsigned_tx.input.len() >= 2,
            "expected seller + buyer inputs"
        );
        assert_eq!(
            psbt.unsigned_tx.input[0].previous_output, request.seller_outpoint,
            "seller input must be first to keep inscription sats ahead of fee tail"
        );

        assert!(
            psbt.unsigned_tx.output.len() >= 2,
            "expected buyer postage and seller payout outputs"
        );
        assert_eq!(
            psbt.unsigned_tx.output[0].value,
            Amount::from_sat(request.seller_output_value_sats),
            "buyer postage output must be first"
        );
        assert_eq!(
            psbt.unsigned_tx.output[0].script_pubkey, buyer_receive_script,
            "first output must be buyer receive script"
        );
        assert_eq!(
            psbt.unsigned_tx.output[1].value,
            Amount::from_sat(request.ask_sats + request.seller_output_value_sats),
            "seller payout output must be second"
        );
        assert_eq!(
            psbt.unsigned_tx.output[1].script_pubkey, seller_script,
            "second output must be seller payout script"
        );
        assert!(
            psbt.unsigned_tx.output.len() > 2,
            "offer should include change output routed to main address"
        );
        for output in psbt.unsigned_tx.output.iter().skip(2) {
            assert_eq!(
                output.script_pubkey, expected_change_script,
                "change output must be routed to main external address"
            );
        }
    }
}

#[test]
fn create_offer_rejects_non_main_seller_payout_address() {
    let mut wallet = funded_unified_wallet(true);

    let seller_seed = [11u8; 64];
    let mut seller_wallet =
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seller_seed))
            .with_scheme(AddressScheme::Dual)
            .build()
            .expect("seller wallet build");
    let seller_input_address = seller_wallet
        .next_taproot_address()
        .expect("seller taproot address")
        .to_string();
    let non_main_seller_payout_address = seller_wallet
        .get_payment_address()
        .expect("seller payment address")
        .to_string();
    assert_ne!(seller_input_address, non_main_seller_payout_address);

    let seller_txid =
        Txid::from_str("95fd55da0385b869a2a7f67eee798f64abcfc85929ae52407d4f8e5983c98757")
            .expect("txid");
    let request = CreateOfferRequest {
        inscription_id: "95fd55da0385b869a2a7f67eee798f64abcfc85929ae52407d4f8e5983c98757i1"
            .to_string(),
        seller_outpoint: OutPoint::new(seller_txid, 1),
        seller_input_address: seller_input_address.clone(),
        seller_payout_address: non_main_seller_payout_address.clone(),
        seller_output_value_sats: 330,
        ask_sats: 123_456,
        fee_rate_sat_vb: 1,
        created_at_unix: 1_710_000_000,
        expires_at_unix: 1_710_003_600,
        nonce: 777,
        publisher_pubkey_hex: None,
    };

    let err = wallet.create_offer(&request).expect_err("must fail");
    assert!(
        err.to_string()
            .contains("seller_payout_address must match wallet main payment address"),
        "unexpected error: {err}"
    );
}
