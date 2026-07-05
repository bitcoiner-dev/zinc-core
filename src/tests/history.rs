//! Coverage for `history.rs::get_transactions` and its helpers: send/receive labeling, fee,
//! confirmation status, inscription attachment, parent-txid collection, cross-wallet dedup
//! (amount summed), unconfirmed-first / newest-first sorting, and the `limit` cap.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder};
    use crate::ordinals::types::{Inscription, Satpoint};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
    use bdk_wallet::KeychainKind;

    fn dummy_tx(value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = uid;
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(hash_bytes), 0),
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn spend_tx(prev: OutPoint, value: u64, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    /// Apply transactions to a wallet. `Some(height)` anchors as confirmed; `None` marks seen
    /// (unconfirmed/mempool).
    fn fund(wallet: &mut bdk_wallet::Wallet, txs: &[(&Transaction, Option<u32>)], last_index: u32) {
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let hash = BlockHash::all_zeros();
        // Extend the wallet's checkpoint chain so anchored blocks count as confirmed.
        let mut cp = wallet.latest_checkpoint();
        for (tx, height) in txs {
            let _ = graph.insert_tx((*tx).clone());
            match height {
                Some(h) => {
                    let _ = graph.insert_anchor(
                        (*tx).compute_txid(),
                        ConfirmationBlockTime {
                            block_id: BlockId { height: *h, hash },
                            confirmation_time: 1000 + u64::from(*h),
                        },
                    );
                    cp = cp.insert(BlockId { height: *h, hash });
                }
                None => {
                    let _ = graph.insert_seen_at((*tx).compute_txid(), 5000);
                }
            }
        }
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, last_index);
        wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Some(cp),
                last_active_indices: last,
            })
            .unwrap();
    }

    fn unified() -> crate::builder::ZincWallet {
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap()
    }

    #[test]
    fn receive_tx_is_labeled_and_amounts_match() {
        let mut w = unified();
        let addr = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let tx = dummy_tx(50_000, addr.script_pubkey(), 1);
        fund(&mut w.vault_wallet, &[(&tx, Some(100))], 0);

        let txs = w.get_transactions(50);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].tx_type, "receive");
        assert_eq!(txs[0].amount_sats, 50_000);
        assert!(txs[0].confirmation_time.is_some());
        assert!(
            !txs[0].parent_txids.is_empty(),
            "funding input recorded as a parent txid"
        );
    }

    #[test]
    fn spend_tx_is_labeled_send_with_negative_amount() {
        let mut w = unified();
        let addr = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let spk = addr.script_pubkey();

        // External (non-wallet) destination for the spend.
        let other = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([9u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let ext_spk = other.peek_taproot_address(0).script_pubkey();

        let fund_tx = dummy_tx(50_000, spk, 1);
        let spend = spend_tx(OutPoint::new(fund_tx.compute_txid(), 0), 40_000, ext_spk);
        fund(
            &mut w.vault_wallet,
            &[(&fund_tx, Some(100)), (&spend, Some(101))],
            0,
        );

        let txs = w.get_transactions(50);
        let send = txs
            .iter()
            .find(|t| t.txid == spend.compute_txid().to_string())
            .expect("spend tx present");
        assert_eq!(send.tx_type, "send");
        assert!(
            send.amount_sats < 0,
            "spend reduces balance: {}",
            send.amount_sats
        );
    }

    #[test]
    fn sorts_unconfirmed_first_then_newest_confirmed() {
        let mut w = unified();
        let addr = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let spk = addr.script_pubkey();

        let old = dummy_tx(10_000, spk.clone(), 1); // height 100
        let new = dummy_tx(20_000, spk.clone(), 2); // height 200
        let pending = dummy_tx(30_000, spk, 3); // unconfirmed
        fund(
            &mut w.vault_wallet,
            &[(&old, Some(100)), (&new, Some(200)), (&pending, None)],
            0,
        );

        let txs = w.get_transactions(50);
        assert_eq!(txs.len(), 3);
        assert_eq!(
            txs[0].txid,
            pending.compute_txid().to_string(),
            "unconfirmed first"
        );
        assert!(txs[0].confirmation_time.is_none());
        assert_eq!(
            txs[1].txid,
            new.compute_txid().to_string(),
            "newest confirmed next"
        );
        assert_eq!(
            txs[2].txid,
            old.compute_txid().to_string(),
            "oldest confirmed last"
        );
    }

    #[test]
    fn limit_caps_the_number_of_results() {
        let mut w = unified();
        let addr = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let spk = addr.script_pubkey();
        let a = dummy_tx(10_000, spk.clone(), 1);
        let b = dummy_tx(20_000, spk.clone(), 2);
        let c = dummy_tx(30_000, spk, 3);
        fund(
            &mut w.vault_wallet,
            &[(&a, Some(100)), (&b, Some(101)), (&c, Some(102))],
            0,
        );

        assert_eq!(w.get_transactions(2).len(), 2);
    }

    #[test]
    fn dedup_merges_same_txid_across_dual_wallets() {
        let mut w = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Dual)
            .build()
            .unwrap();
        let vault_spk = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();
        let pay_spk = w
            .payment_wallet
            .as_mut()
            .unwrap()
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();

        // One tx paying both the vault and the payment branch.
        let mut tx = dummy_tx(10_000, vault_spk, 1);
        tx.output.push(TxOut {
            value: Amount::from_sat(7_000),
            script_pubkey: pay_spk,
        });

        fund(&mut w.vault_wallet, &[(&tx, Some(100))], 0);
        fund(w.payment_wallet.as_mut().unwrap(), &[(&tx, Some(100))], 0);

        let txs = w.get_transactions(50);
        assert_eq!(txs.len(), 1, "same txid from both wallets is deduplicated");
        assert_eq!(
            txs[0].amount_sats, 17_000,
            "amounts from both branches are summed"
        );
    }

    #[test]
    fn inscriptions_are_attached_to_their_transaction() {
        let mut w = unified();
        let addr = w
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        let tx = dummy_tx(10_000, addr.script_pubkey(), 1);
        fund(&mut w.vault_wallet, &[(&tx, Some(100))], 0);

        let op = OutPoint::new(tx.compute_txid(), 0);
        w.inscriptions.push(Inscription {
            id: "insc-xyz".to_string(),
            number: 7,
            satpoint: Satpoint {
                outpoint: op,
                offset: 0,
            },
            content_type: Some("text/plain".to_string()),
            value: Some(10_000),
            content_length: None,
            timestamp: None,
        });

        let txs = w.get_transactions(50);
        assert_eq!(txs[0].inscriptions.len(), 1);
        assert_eq!(txs[0].inscriptions[0].id, "insc-xyz");
        assert_eq!(txs[0].inscriptions[0].number, 7);
    }
}
