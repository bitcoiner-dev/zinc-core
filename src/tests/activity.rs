use crate::{
    builder::{Seed64, SyncSleeper, WalletBuilder},
    ZincWallet,
};
use bitcoin::{
    hashes::{sha256, Hash},
    Amount, Network, OutPoint, Transaction, TxIn, TxOut,
};
use serde_json::{json, Value};

fn wallet() -> ZincWallet {
    WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([9; 64]))
        .build()
        .unwrap()
}

fn tx(wallet: &ZincWallet, height: u32, dual: bool) -> Value {
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: wallet.peek_taproot_address(0).script_pubkey(),
    }];
    if dual {
        outputs.push(TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: wallet.peek_payment_address(0).unwrap().script_pubkey(),
        });
    }
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(height),
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0),
            ..Default::default()
        }],
        output: outputs,
    };
    json!({"txid": tx.compute_txid(), "version": 2, "locktime": height,
        "vin": [{"txid": tx.input[0].previous_output.txid, "vout":0, "scriptsig":"", "sequence": tx.input[0].sequence.to_consensus_u32(), "is_coinbase":false,
            "prevout":{"value":10000,"scriptpubkey":""}}],
        "vout":tx.output.iter().map(|out|json!({"value":out.value.to_sat(),"scriptpubkey":out.script_pubkey.to_hex_string()})).collect::<Vec<_>>(),
        "size":tx.total_size(), "weight":tx.weight().to_wu(), "fee":7000,
        "status":{"confirmed":true,"block_height":height,"block_time":u64::from(height)+10000,"block_hash":"07".repeat(32)} })
}

fn script_path(script: &bitcoin::Script) -> String {
    format!("/scripthash/{}", sha256::Hash::hash(script.as_bytes()))
}

async fn empty_change(
    server: &mut mockito::Server,
    wallet: &ZincWallet,
) -> Vec<mockito::Mock> {
    let mut mocks = Vec::new();
    for w in std::iter::once(&wallet.vault_wallet).chain(wallet.payment_wallet.iter()) {
        let script = w
            .peek_address(bdk_wallet::KeychainKind::Internal, 0)
            .script_pubkey();
        mocks.push(
            server
                .mock("GET", format!("{}/txs", script_path(&script)).as_str())
                .with_body("[]")
                .create_async()
                .await,
        );
    }
    mocks
}

#[tokio::test]
async fn twenty_rows_fetch_one_wire_page_and_reuse_five_extras() {
    let mut wallet = wallet();
    let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
    let _empty = empty_change(&mut server, &wallet).await;
    let path = script_path(&wallet.peek_taproot_address(0).script_pubkey());
    let rows: Vec<_> = (76..=100)
        .rev()
        .map(|height| tx(&wallet, height, false))
        .collect();
    let first = server
        .mock("GET", format!("{path}/txs").as_str())
        .with_body(json!(rows).to_string())
        .expect(1)
        .create_async()
        .await;
    let older = server
        .mock(
            "GET",
            format!("{path}/txs/chain/{}", rows[24]["txid"].as_str().unwrap()).as_str(),
        )
        .with_body(
            json!((51..=75)
                .rev()
                .map(|height| tx(&wallet, height, false))
                .collect::<Vec<_>>())
            .to_string(),
        )
        .expect(0)
        .create_async()
        .await;
    let client = esplora_client::Builder::new(&server.url())
        .max_retries(0)
        .build_async_with_sleeper::<SyncSleeper>()
        .unwrap();
    let pager = wallet.prepare_activity_page(&server.url(), None).unwrap();
    let (pager, page) = pager.fetch(&client, 20).await.unwrap();
    assert_eq!(page.items.len(), 20);
    assert_eq!(page.items[0].txid, rows[0]["txid"].as_str().unwrap());
    assert!(page.has_more);
    wallet.retain_activity_page(pager, &page).unwrap();
    let pager = wallet
        .prepare_activity_page(&server.url(), page.next_cursor.as_deref())
        .unwrap();
    let (_, next) = pager.fetch(&client, 3).await.unwrap();
    assert_eq!(next.items.len(), 3);
    assert_eq!(next.items[0].txid, rows[20]["txid"].as_str().unwrap());
    first.assert_async().await;
    older.assert_async().await;
}

#[tokio::test]
async fn dual_address_transactions_are_merged_without_double_counting() {
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([9; 64]))
        .with_scheme(crate::AddressScheme::Dual)
        .build()
        .unwrap();
    let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
    let _empty = empty_change(&mut server, &wallet).await;
    let rows: Vec<_> = (1..=10)
        .rev()
        .map(|height| tx(&wallet, height, true))
        .collect();
    let mut mocks = Vec::new();
    for address in [
        wallet.peek_taproot_address(0),
        wallet.peek_payment_address(0).unwrap(),
    ] {
        mocks.push(
            server
                .mock(
                    "GET",
                    format!("{}/txs", script_path(&address.script_pubkey())).as_str(),
                )
                .with_body(json!(rows).to_string())
                .expect(1)
                .create_async()
                .await,
        );
    }
    let client = esplora_client::Builder::new(&server.url())
        .max_retries(0)
        .build_async_with_sleeper::<SyncSleeper>()
        .unwrap();
    let (pager, page) = wallet
        .prepare_activity_page(&server.url(), None)
        .unwrap()
        .fetch(&client, 20)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 10);
    assert!(page.items.iter().all(|tx| tx.amount_sats == 3000));
    assert!(!page.has_more);
    wallet.retain_activity_page(pager, &page).unwrap();
    for mock in mocks {
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn cursors_reject_other_backend_and_retired_account_generation() {
    let mut wallet = wallet();
    let pager = wallet
        .prepare_activity_page("https://example.test", None)
        .unwrap();
    let cursor = pager.cursor();
    let page = crate::history::TransactionPage {
        items: Vec::new(),
        next_cursor: None,
        has_more: false,
    };
    wallet.retain_activity_page(pager, &page).unwrap();
    assert!(wallet
        .prepare_activity_page("https://different.test", Some(&cursor))
        .is_err());
    wallet.retire_inflight_sync();
    assert!(wallet
        .prepare_activity_page("https://example.test", Some(&cursor))
        .is_err());
}

#[tokio::test]
async fn continuation_fetches_only_the_next_wire_page_and_replays_without_network() {
    let mut wallet = wallet();
    let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
    let _empty = empty_change(&mut server, &wallet).await;
    let path = script_path(&wallet.peek_taproot_address(0).script_pubkey());
    let rows: Vec<_> = (76..=100)
        .rev()
        .map(|height| tx(&wallet, height, false))
        .collect();
    let first = server
        .mock("GET", format!("{path}/txs").as_str())
        .with_body(json!(rows).to_string())
        .expect(1)
        .create_async()
        .await;
    let second = server
        .mock(
            "GET",
            format!("{path}/txs/chain/{}", rows[24]["txid"].as_str().unwrap()).as_str(),
        )
        .with_body(
            json!((51..=75)
                .rev()
                .map(|height| tx(&wallet, height, false))
                .collect::<Vec<_>>())
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let client = esplora_client::Builder::new(&server.url())
        .max_retries(0)
        .build_async_with_sleeper::<SyncSleeper>()
        .unwrap();
    let (pager, page) = wallet
        .prepare_activity_page(&server.url(), None)
        .unwrap()
        .fetch(&client, 20)
        .await
        .unwrap();
    wallet.retain_activity_page(pager, &page).unwrap();
    let cursor = page.next_cursor.clone().unwrap();
    let (pager, next) = wallet
        .prepare_activity_page(&server.url(), Some(&cursor))
        .unwrap()
        .fetch(&client, 20)
        .await
        .unwrap();
    assert_eq!(next.items.len(), 20);
    assert_eq!(next.items[0].txid, rows[20]["txid"].as_str().unwrap());
    assert_eq!(
        next.items[19].txid,
        tx(&wallet, 61, false)["txid"].as_str().unwrap()
    );
    assert!(next.has_more);
    wallet.retain_activity_page(pager, &next).unwrap();
    let (_, replay) = wallet
        .prepare_activity_page(&server.url(), Some(&cursor))
        .unwrap()
        .fetch(&client, 20)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(replay).unwrap(),
        serde_json::to_value(next).unwrap()
    );
    first.assert_async().await;
    second.assert_async().await;
}

#[tokio::test]
async fn malformed_activity_cannot_create_spend_authority() {
    let mut wallet = wallet();
    let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
    let _empty = empty_change(&mut server, &wallet).await;
    let mut row = tx(&wallet, 100, false);
    row["vout"][0]["value"] = json!(999999);
    let _bad = server
        .mock(
            "GET",
            format!(
                "{}/txs",
                script_path(&wallet.peek_taproot_address(0).script_pubkey())
            )
            .as_str(),
        )
        .with_body(json!([row]).to_string())
        .create_async()
        .await;
    let client = esplora_client::Builder::new(&server.url())
        .max_retries(0)
        .build_async_with_sleeper::<SyncSleeper>()
        .unwrap();
    assert!(wallet
        .prepare_activity_page(&server.url(), None)
        .unwrap()
        .fetch(&client, 20)
        .await
        .is_err());
    assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
    assert!(wallet.chain_observed_at_unix.is_none());
    assert!(!wallet.ordinals_verified());
}
