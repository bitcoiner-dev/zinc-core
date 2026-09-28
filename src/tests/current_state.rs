use crate::{
    builder::{Seed64, WalletBuilder},
    current_state::CurrentStateUpdate,
    ZincWallet,
};
use bdk_chain::{BlockId, ConfirmationBlockTime};
use bdk_wallet::KeychainKind;
use bitcoin::{hashes::Hash, Amount, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut};
use std::collections::{BTreeMap, BTreeSet};

fn wallet() -> ZincWallet {
    WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([37; 64]))
        .build()
        .unwrap()
}

fn funding(wallet: &ZincWallet) -> Transaction {
    let script = wallet.peek_taproot_address(0).script_pubkey();
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([3; 32]), 0),
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script.clone(),
            },
            TxOut {
                value: Amount::from_sat(900_000),
                script_pubkey: script,
            },
        ],
    }
}

fn update(wallet: &ZincWallet, tx: &Transaction, include: &[u32]) -> CurrentStateUpdate {
    let block = BlockId {
        height: 200,
        hash: BlockHash::from_byte_array([7; 32]),
    };
    let mut graph = bdk_chain::TxGraph::default();
    let _ = graph.insert_tx(tx.clone());
    let _ = graph.insert_anchor(
        tx.compute_txid(),
        ConfirmationBlockTime {
            block_id: block,
            confirmation_time: 1000,
        },
    );
    CurrentStateUpdate {
        update: bdk_wallet::Update {
            chain: Some(wallet.vault_wallet.latest_checkpoint().insert(block)),
            tx_update: graph.into(),
            last_active_indices: BTreeMap::from([(KeychainKind::External, 0)]),
        },
        outputs: include
            .iter()
            .map(|vout| {
                (
                    OutPoint::new(tx.compute_txid(), *vout),
                    tx.output[*vout as usize].clone(),
                )
            })
            .collect(),
        active_scripts: BTreeSet::from([tx.output[0].script_pubkey.clone()]),
    }
}

#[test]
fn spent_sibling_never_appears_in_balance_assets_or_coin_selection() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    // BDK has both outputs, but the current-output authority has just one.
    assert_eq!(wallet.vault_wallet.list_unspent().count(), 2);
    assert_eq!(wallet.list_utxos().len(), 1);
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 50_000);
    assert_eq!(wallet.collect_utxo_snapshots().len(), 1);
    assert!(wallet
        .unavailable_outpoints()
        .contains(&OutPoint::new(tx.compute_txid(), 1)));
    assert!(wallet
        .current_unspent(&wallet.vault_wallet)
        .all(|u| u.outpoint.vout == 0));
    // Exercise the actual BDK selector, not just the public UTXO list. The
    // 900k sibling is in the graph but must never fund a transaction.
    wallet.ordinals_verified = true;
    let recipient = wallet.peek_taproot_address(3).to_string().parse().unwrap();
    let request = crate::builder::CreatePsbtRequest {
        recipient,
        amount: Amount::from_sat(10_000),
        fee_rate: bitcoin::FeeRate::from_sat_per_vb(1).unwrap(),
    };
    let psbt = wallet.create_psbt_tx(&request).unwrap();
    assert!(psbt
        .unsigned_tx
        .input
        .iter()
        .all(|i| i.previous_output.vout == 0));
    let excessive = crate::builder::CreatePsbtRequest {
        amount: Amount::from_sat(100_000),
        ..request
    };
    assert!(wallet.create_psbt_tx(&excessive).is_err());
}

#[test]
fn current_output_authority_survives_restart_without_authorizing_signing() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let json = serde_json::to_string(&wallet.export_changeset().unwrap()).unwrap();
    let restored = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([37; 64]))
        .with_persistence(&json)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(restored.get_raw_balance().total().to_sat(), 50_000);
    assert!(!restored.ordinals_verified());
    assert!(restored.chain_observed_at_unix.is_none());
    // An address with only old/spent activity must not be reused on restart.
    assert!(!restored
        .vault_wallet
        .list_unused_addresses(KeychainKind::External)
        .any(|a| a.index == 0));
}

#[test]
fn disappearing_output_retires_asset_authority_even_without_a_spending_transaction() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let generation = wallet.chain_state_generation();
    wallet.ordinals_verified = true;
    wallet
        .apply_current_state(update(&wallet, &tx, &[]), None)
        .unwrap();
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    assert!(wallet.chain_state_generation() > generation);
    assert!(!wallet.ordinals_verified());
}

#[test]
fn identical_snapshot_does_not_retire_asset_generation() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let generation = wallet.chain_state_generation();
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    assert_eq!(wallet.chain_state_generation(), generation);
}

#[test]
fn invalid_funding_output_fails_closed() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    let mut result = update(&wallet, &tx, &[0]);
    result.outputs.values_mut().next().unwrap().value = Amount::from_sat(1);
    assert!(wallet.apply_current_state(result, None).is_err());
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    assert!(!wallet.ordinals_verified());
}

#[test]
fn missing_payment_read_cannot_replace_previous_authority() {
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([37; 64]))
        .with_scheme(crate::AddressScheme::Dual)
        .build()
        .unwrap();
    let tx = funding(&wallet);
    assert!(wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .is_err());
    assert_eq!(wallet.vault_wallet.list_unspent().count(), 0);
}

#[tokio::test]
async fn high_activity_current_state_never_requests_history() {
    use crate::builder::{SyncRequestType, SyncSleeper};
    use bitcoin::hashes::sha256;
    use serde_json::json;
    let wallet = wallet();
    let tx = funding(&wallet);
    let script = tx.output[0].script_pubkey.clone();
    let path = format!("/scripthash/{}", sha256::Hash::hash(script.as_bytes()));
    let mut server = mockito::Server::new_async().await;
    let history = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/scripthash/.*/txs.*".into()),
        )
        .expect(0)
        .with_status(500)
        .create_async()
        .await;
    let tip = server
        .mock("GET", "/blocks/tip/hash")
        .with_body("07".repeat(32))
        .expect(2)
        .create_async()
        .await;
    let stats = server.mock("GET", path.as_str()).with_body(json!({
        "chain_stats":{"tx_count":100000,"funded_txo_count":200000,"funded_txo_sum":999999999,
            "spent_txo_count":199999,"spent_txo_sum":999949999},
        "mempool_stats":{"tx_count":0,"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0}
    }).to_string()).expect(1).create_async().await;
    let utxos = server
        .mock("GET", format!("{path}/utxo").as_str())
        .with_body(
            json!([{
                "txid":tx.compute_txid(),"vout":0,"value":50000,"status":{"confirmed":false}
            }])
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let funding = server.mock("GET", format!("/tx/{}",tx.compute_txid()).as_str()).with_body(json!({
        "txid":tx.compute_txid(),"version":2,"locktime":0,
        "vin":[{"txid":tx.input[0].previous_output.txid,"vout":0,"prevout":{"scriptpubkey":"","value":951000},
            "scriptsig":"","sequence":tx.input[0].sequence.to_consensus_u32(),"is_coinbase":false}],
        "vout":tx.output.iter().map(|out|json!({"scriptpubkey":out.script_pubkey.to_hex_string(),"value":out.value.to_sat()})).collect::<Vec<_>>(),
        "size":tx.total_size(),"weight":tx.weight().to_wu(),"fee":1000,"status":{"confirmed":false}
    }).to_string()).expect(1).create_async().await;
    let spend = server
        .mock(
            "GET",
            format!("/tx/{}/outspend/0", tx.compute_txid()).as_str(),
        )
        .with_body(r#"{"spent":false}"#)
        .expect(1)
        .create_async()
        .await;
    let client = esplora_client::Builder::new(&server.url())
        .max_retries(0)
        .build_async_with_sleeper::<SyncSleeper>()
        .unwrap();
    let request = bdk_chain::spk_client::SyncRequest::<(KeychainKind, u32)>::builder_at(1000)
        .spks_with_indexes([((KeychainKind::External, 0), script)])
        .build();
    let result =
        crate::current_state::fetch_esplora(&client, SyncRequestType::Incremental(request), 5, 5)
            .await
            .unwrap();
    assert_eq!(result.outputs.len(), 1);
    assert_eq!(
        result.outputs.values().next().unwrap().value.to_sat(),
        50000
    );
    for mock in [history, tip, stats, utxos, funding, spend] {
        mock.assert_async().await;
    }
}
