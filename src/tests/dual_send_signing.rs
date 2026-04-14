use crate::builder::{AddressScheme, CreatePsbtRequest, PaymentAddressType, Seed64, SignOptions, WalletBuilder};
use base64::Engine;
use bdk_wallet::bitcoin::hashes::{hash160, Hash};
use bdk_wallet::bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::ConfirmationBlockTime;
use bdk_wallet::KeychainKind;
use bitcoin::psbt::Psbt;

fn create_dummy_tx(output_value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[31] = uid;
    let dummy_txid = Txid::from_byte_array(hash_bytes);

    let dummy_input = bdk_wallet::bitcoin::TxIn {
        previous_output: bdk_wallet::bitcoin::OutPoint::new(dummy_txid, 0),
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

fn fund_payment_wallet(wallet: &mut crate::builder::ZincWallet, value: u64, uid: u8) -> TxOut {
    let payment_wallet = wallet
        .payment_wallet
        .as_mut()
        .expect("dual wallet should include payment wallet");
    let payment_script = payment_wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .script_pubkey();

    let tx = create_dummy_tx(value, payment_script, uid);
    let prevout = tx.output[0].clone();
    let mut graph = bdk_wallet::chain::TxGraph::default();
    let block_hash = bdk_wallet::bitcoin::BlockHash::all_zeros();

    let _ = graph.insert_tx(tx.clone());
    let _ = graph.insert_anchor(
        tx.compute_txid(),
        ConfirmationBlockTime {
            block_id: bdk_wallet::chain::BlockId {
                height: 100,
                hash: block_hash,
            },
            confirmation_time: 1_000,
        },
    );

    let mut last_active = std::collections::BTreeMap::new();
    last_active.insert(KeychainKind::External, 0);
    let update = bdk_wallet::Update {
        tx_update: graph.into(),
        chain: Default::default(),
        last_active_indices: last_active,
    };

    payment_wallet.apply_update(update).expect("payment update");
    prevout
}

fn finalized_pubkey_matches_native_witness(prevout: &TxOut, witness: &bitcoin::Witness) -> bool {
    let script = prevout.script_pubkey.as_bytes();
    if script.len() != 22 || script[0] != 0x00 || script[1] != 0x14 {
        return false;
    }
    let pubkey = match witness.iter().nth(1) {
        Some(bytes) => bytes,
        None => return false,
    };
    let pubkey_hash = hash160::Hash::hash(pubkey);
    script[2..22] == pubkey_hash[..]
}

fn finalized_pubkey_matches_nested_witness(
    prevout: &TxOut,
    script_sig: &bitcoin::ScriptBuf,
    witness: &bitcoin::Witness,
) -> bool {
    let prevout_script = prevout.script_pubkey.as_bytes();
    if prevout_script.len() != 23
        || prevout_script[0] != 0xa9
        || prevout_script[1] != 0x14
        || prevout_script[22] != 0x87
    {
        return false;
    }

    let script_sig_bytes = script_sig.as_bytes();
    if script_sig_bytes.len() != 23 || script_sig_bytes[0] != 0x16 || script_sig_bytes[1] != 0x00 || script_sig_bytes[2] != 0x14 {
        return false;
    }

    let redeem_script = &script_sig_bytes[1..23];
    let redeem_hash = hash160::Hash::hash(redeem_script);
    if prevout_script[2..22] != redeem_hash[..] {
        return false;
    }

    let pubkey = match witness.iter().nth(1) {
        Some(bytes) => bytes,
        None => return false,
    };
    let pubkey_hash = hash160::Hash::hash(pubkey);
    redeem_script[2..22] == pubkey_hash[..]
}

fn assert_payment_send_finalizes_correctly(payment_type: PaymentAddressType) {
    let seed = [11u8; 64];
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_payment_address_type(payment_type)
        .build()
        .expect("dual wallet");

    wallet.apply_verified_ordinals_update(vec![], std::collections::HashSet::new(), vec![]);
    let prevout = fund_payment_wallet(&mut wallet, 100_000, 3);

    let recipient = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([12u8; 64]))
        .with_scheme(AddressScheme::Dual)
        .with_payment_address_type(payment_type)
        .build()
        .expect("recipient wallet")
        .peek_payment_address(0)
        .expect("recipient payment address")
        .to_string();

    let request = CreatePsbtRequest::from_parts(&recipient, 40_000, 1).expect("request");
    let unsigned_psbt = wallet.create_psbt_base64(&request).expect("create send psbt");
    let signed_psbt = wallet
        .sign_psbt(
            &unsigned_psbt,
            Some(SignOptions {
                sign_inputs: None,
                sighash: None,
                finalize: true,
            }),
        )
        .expect("sign and finalize");

    let signed_bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_psbt)
        .expect("decode signed psbt");
    let signed = Psbt::deserialize(&signed_bytes).expect("signed psbt");
    let extracted = signed.extract_tx().expect("extract tx");

    assert_eq!(extracted.input.len(), 1, "expected a single funded input");
    let input = &extracted.input[0];

    let is_valid = match payment_type {
        PaymentAddressType::NativeSegwit => {
            finalized_pubkey_matches_native_witness(&prevout, &input.witness)
        }
        PaymentAddressType::NestedSegwit => {
            finalized_pubkey_matches_nested_witness(&prevout, &input.script_sig, &input.witness)
        }
        PaymentAddressType::Legacy => true,
    };

    assert!(
        is_valid,
        "finalized witness/script does not match the payment prevout for {:?}: prevout_script={}, script_sig={}, witness={:?}",
        payment_type,
        prevout.script_pubkey,
        input.script_sig,
        input.witness
    );
}

#[test]
fn test_dual_native_payment_send_finalizes_with_matching_witness() {
    assert_payment_send_finalizes_correctly(PaymentAddressType::NativeSegwit);
}

#[test]
fn test_dual_nested_payment_send_finalizes_with_matching_witness() {
    assert_payment_send_finalizes_correctly(PaymentAddressType::NestedSegwit);
}
