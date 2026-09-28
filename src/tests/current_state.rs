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

fn spending(tx: &Transaction) -> Transaction {
    Transaction {
        input: vec![TxIn {
            previous_output: OutPoint::new(tx.compute_txid(), 0),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
        ..tx.clone()
    }
}

fn monitored_transactions(wallet: &ZincWallet) -> BTreeSet<bitcoin::Txid> {
    match wallet.prepare_requests(false).taproot {
        crate::builder::SyncRequestType::Incremental(mut request) => request.iter_txids().collect(),
        crate::builder::SyncRequestType::Full(_) => {
            panic!("an initialized wallet must sync incrementally")
        }
    }
}

#[test]
fn bdk_selects_replacement_without_forgetting_original_spend() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let original = spending(&tx);
    let mut pending = update(&wallet, &tx, &[]);
    pending.update.tx_update.txs.push(original.clone().into());
    pending
        .update
        .tx_update
        .seen_ats
        .insert((original.compute_txid(), 1001));
    wallet.apply_current_state(pending, None).unwrap();
    assert!(monitored_transactions(&wallet).contains(&original.compute_txid()));

    let mut replacement = original.clone();
    replacement.output[0].value = Amount::from_sat(48_000);
    replacement.output[0].script_pubkey = wallet.peek_taproot_address(0).script_pubkey();
    let mut replaced = update(&wallet, &tx, &[]);
    replaced
        .update
        .tx_update
        .txs
        .push(replacement.clone().into());
    replaced
        .update
        .tx_update
        .seen_ats
        .insert((replacement.compute_txid(), 1002));
    replaced.outputs.insert(
        OutPoint::new(replacement.compute_txid(), 0),
        replacement.output[0].clone(),
    );
    wallet.apply_current_state(replaced, None).unwrap();
    assert!(wallet
        .vault_wallet
        .get_tx(original.compute_txid())
        .is_none());
    assert!(wallet
        .vault_wallet
        .tx_graph()
        .get_tx(original.compute_txid())
        .is_some());
    assert_eq!(wallet.list_utxos().len(), 1);
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 48_000);
    assert!(!wallet.asset_state_is_current());
}

#[test]
fn confirmed_spender_cannot_be_evicted_by_a_conflicting_utxo_response() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let spend = spending(&tx);
    let block = BlockId {
        height: 201,
        hash: BlockHash::from_byte_array([8; 32]),
    };
    let mut confirmed = update(&wallet, &tx, &[]);
    confirmed.update.chain = Some(wallet.vault_wallet.latest_checkpoint().insert(block));
    confirmed.update.tx_update.txs.push(spend.clone().into());
    confirmed.update.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: block,
            confirmation_time: 1001,
        },
        spend.compute_txid(),
    ));
    wallet.apply_current_state(confirmed, None).unwrap();
    assert!(monitored_transactions(&wallet).contains(&spend.compute_txid()));
    assert!(wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .is_err());
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    assert!(matches!(
        wallet
            .vault_wallet
            .get_tx(spend.compute_txid())
            .unwrap()
            .chain_position,
        bdk_chain::ChainPosition::Confirmed { .. }
    ));
    assert!(!wallet.asset_state_is_current());
}

#[test]
fn bdk_retains_pending_spend_across_restart_then_reconciles_eviction() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let spend = spending(&tx);
    let mut pending = update(&wallet, &tx, &[]);
    pending.update.tx_update.txs.push(spend.clone().into());
    pending
        .update
        .tx_update
        .seen_ats
        .insert((spend.compute_txid(), 1001));
    wallet.apply_current_state(pending, None).unwrap();
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    let persistence = serde_json::to_string(&wallet.export_changeset().unwrap()).unwrap();
    let mut restored = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([37; 64]))
        .with_persistence(&persistence)
        .unwrap()
        .build()
        .unwrap();
    assert!(restored.vault_wallet.get_tx(spend.compute_txid()).is_some());
    restored
        .apply_current_state(update(&restored, &tx, &[0]), None)
        .unwrap();
    assert_eq!(restored.get_raw_balance().total().to_sat(), 50_000);
    assert!(restored.vault_wallet.get_tx(spend.compute_txid()).is_none());
    assert!(
        restored
            .vault_wallet
            .tx_graph()
            .get_tx(spend.compute_txid())
            .is_some(),
        "BDK retains the historical transaction"
    );
    assert!(
        !restored.asset_state_is_current(),
        "returning coins must be reclassified by Ord"
    );
}

#[test]
fn bdk_handles_deep_reorg_without_deleting_confirmed_spend_records() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let spend = spending(&tx);
    let spend_block = BlockId {
        height: 201,
        hash: BlockHash::from_byte_array([8; 32]),
    };
    let old_tip = BlockId {
        height: 210,
        hash: BlockHash::from_byte_array([9; 32]),
    };
    let mut confirmed = update(&wallet, &tx, &[]);
    confirmed.update.chain = Some(
        wallet
            .vault_wallet
            .latest_checkpoint()
            .insert(spend_block)
            .insert(old_tip),
    );
    confirmed.update.tx_update.txs.push(spend.clone().into());
    confirmed.update.tx_update.anchors.insert((
        ConfirmationBlockTime {
            block_id: spend_block,
            confirmation_time: 1001,
        },
        spend.compute_txid(),
    ));
    wallet.apply_current_state(confirmed, None).unwrap();
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    assert!(
        !monitored_transactions(&wallet).contains(&spend.compute_txid()),
        "six confirmations retires frequent monitoring, not the historical record"
    );
    let mut reorg = update(&wallet, &tx, &[0]);
    reorg.update.chain = Some(
        wallet
            .vault_wallet
            .latest_checkpoint()
            .insert(BlockId {
                height: 201,
                hash: BlockHash::from_byte_array([10; 32]),
            })
            .insert(BlockId {
                height: 210,
                hash: BlockHash::from_byte_array([11; 32]),
            }),
    );
    let result = wallet.apply_current_state(reorg, None);
    assert!(
        result.is_ok(),
        "{result:?}; checkpoints={:?}; spender={:?}",
        wallet
            .vault_wallet
            .latest_checkpoint()
            .iter()
            .map(|c| c.block_id())
            .collect::<Vec<_>>(),
        wallet
            .vault_wallet
            .get_tx(spend.compute_txid())
            .map(|tx| tx.chain_position)
    );
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 50_000);
    assert!(wallet
        .vault_wallet
        .tx_graph()
        .get_tx(spend.compute_txid())
        .is_some());
    assert!(!wallet.asset_state_is_current());
}

#[test]
fn stale_ord_response_is_rejected_and_unclassified_returning_coins_stay_protected() {
    let mut wallet = wallet();
    let tx = funding(&wallet);
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let before = wallet.chain_state_generation();
    wallet.mark_current_wallet_outpoints_classified_for_test();
    wallet
        .apply_current_state(update(&wallet, &tx, &[]), None)
        .unwrap();
    assert!(wallet
        .apply_verified_ordinals_update(
            vec![],
            Default::default(),
            vec![],
            Default::default(),
            before
        )
        .is_err());
    wallet
        .apply_current_state(update(&wallet, &tx, &[0]), None)
        .unwrap();
    let current = wallet.chain_state_generation();
    wallet
        .apply_verified_ordinals_update(
            vec![],
            Default::default(),
            vec![],
            Default::default(),
            current,
        )
        .unwrap();
    assert!(wallet
        .inscribed_utxos
        .contains(&OutPoint::new(tx.compute_txid(), 0)));
    assert!(!wallet
        .classified_outpoints
        .contains(&OutPoint::new(tx.compute_txid(), 0)));
    let request = crate::builder::CreatePsbtRequest {
        recipient: wallet.peek_taproot_address(3).to_string().parse().unwrap(),
        amount: Amount::from_sat(10_000),
        fee_rate: bitcoin::FeeRate::from_sat_per_vb(1).unwrap(),
    };
    assert!(wallet.create_psbt_tx(&request).is_err());
}

#[tokio::test]
async fn full_rescan_covers_revealed_addresses_before_applying_stop_gap() {
    use crate::builder::{SyncRequestType, SyncSleeper};
    use serde_json::json;
    for (last_revealed, expected_reads) in [(None, 5), (Some(12), 20)] {
        let wallet = wallet();
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
        let stats = server.mock("GET", mockito::Matcher::Regex("^/scripthash/[^/]+$".into()))
            .with_body(json!({
                "chain_stats":{"tx_count":0,"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0},
                "mempool_stats":{"tx_count":0,"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0}
            }).to_string()).expect(expected_reads).create_async().await;
        let utxos = server
            .mock(
                "GET",
                mockito::Matcher::Regex("^/scripthash/[^/]+/utxo$".into()),
            )
            .with_body("[]")
            .expect(expected_reads)
            .create_async()
            .await;
        let scripts = (0..40)
            .map(|index| (index, wallet.peek_taproot_address(index).script_pubkey()))
            .collect::<Vec<_>>();
        let mut request = bdk_chain::spk_client::FullScanRequest::builder_at(1000)
            .spks_for_keychain(KeychainKind::External, scripts);
        if let Some(index) = last_revealed {
            request = request.last_revealed_for_keychain(KeychainKind::External, index);
        }
        let client = esplora_client::Builder::new(&server.url())
            .max_retries(0)
            .build_async_with_sleeper::<SyncSleeper>()
            .unwrap();
        let result = crate::current_state::fetch_esplora(
            &client,
            SyncRequestType::Full(request.build()),
            5,
            5,
        )
        .await
        .unwrap();
        assert!(result.outputs.is_empty());
        for mock in [history, tip, stats, utxos] {
            mock.assert_async().await;
        }
    }
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
