use crate::builder::{AddressScheme, PaymentAddressType, Seed64, WalletBuilder};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::ConfirmationBlockTime;
use bdk_wallet::KeychainKind;

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

fn apply_confirmed_payment_utxo(wallet: &mut crate::builder::ZincWallet, value: u64, uid: u8) {
    let payment_wallet = wallet
        .payment_wallet
        .as_mut()
        .expect("dual wallet should include payment wallet");
    let payment_script = payment_wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .script_pubkey();

    let tx = create_dummy_tx(value, payment_script, uid);
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
}

#[test]
fn test_account_scoped_persistence_does_not_leak_payment_utxos() {
    let seed = [7u8; 64];

    let mut account0 = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_account_index(0)
        .build()
        .expect("account 0 wallet");
    apply_confirmed_payment_utxo(&mut account0, 50_000, 1);

    let persistence = serde_json::to_string(&account0.export_changeset().expect("persistence"))
        .expect("serialize persistence");

    let account1 = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_account_index(1)
        .with_persistence(&persistence)
        .expect("accept persistence")
        .build()
        .expect("account 1 wallet");

    let payment_unspent: Vec<_> = account1
        .payment_wallet
        .as_ref()
        .expect("dual wallet should include payment wallet")
        .list_unspent()
        .collect();

    assert!(
        payment_unspent.is_empty(),
        "account 1 should not inherit account 0 payment UTXOs from persistence"
    );
}

#[test]
fn test_payment_type_scoped_persistence_does_not_leak_payment_utxos() {
    let seed = [9u8; 64];

    let mut native_wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_payment_address_type(PaymentAddressType::NativeSegwit)
        .build()
        .expect("native payment wallet");
    apply_confirmed_payment_utxo(&mut native_wallet, 75_000, 2);

    let persistence =
        serde_json::to_string(&native_wallet.export_changeset().expect("persistence"))
            .expect("serialize persistence");

    let nested_wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array(seed))
        .with_scheme(AddressScheme::Dual)
        .with_payment_address_type(PaymentAddressType::NestedSegwit)
        .with_persistence(&persistence)
        .expect("accept persistence")
        .build()
        .expect("nested payment wallet");

    let payment_unspent: Vec<_> = nested_wallet
        .payment_wallet
        .as_ref()
        .expect("dual wallet should include payment wallet")
        .list_unspent()
        .collect();

    assert!(
        payment_unspent.is_empty(),
        "nested payment wallet should not inherit native payment UTXOs from persistence"
    );
}
