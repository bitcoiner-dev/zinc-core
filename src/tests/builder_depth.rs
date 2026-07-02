//! Depth coverage for `builder.rs` query/derivation/signing helpers not exercised by the
//! planner/signing suites: ordinals-aware `get_balance` (inscribed filtering, confirmed vs
//! pending), `sign_message` / `sign_bip322_simple_hex`, public-key + pairing-secret getters,
//! `reset_sync_state`, `export_changeset`, and scan helpers.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder, ZincWallet};
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

    fn unified() -> ZincWallet {
        WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap()
    }

    /// Fund a wallet with one UTXO per `(value, confirmed)` entry, returning the outpoints.
    /// Confirmed entries extend the checkpoint chain so they read as confirmed.
    fn fund(wallet: &mut ZincWallet, entries: &[(u64, bool)]) -> Vec<OutPoint> {
        let spk = wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();
        let mut graph = TxGraph::<ConfirmationBlockTime>::default();
        let hash = BlockHash::all_zeros();
        let mut cp = wallet.vault_wallet.latest_checkpoint();
        let mut ops = Vec::new();
        for (i, (value, confirmed)) in entries.iter().enumerate() {
            let tx = dummy_tx(*value, spk.clone(), u8::try_from(i).unwrap() + 1);
            let _ = graph.insert_tx(tx.clone());
            if *confirmed {
                let height = 100 + u32::try_from(i).unwrap();
                let _ = graph.insert_anchor(
                    tx.compute_txid(),
                    ConfirmationBlockTime {
                        block_id: BlockId { height, hash },
                        confirmation_time: 1000 + u64::from(height),
                    },
                );
                cp = cp.insert(BlockId { height, hash });
            } else {
                let _ = graph.insert_seen_at(tx.compute_txid(), 5000);
            }
            ops.push(OutPoint::new(tx.compute_txid(), 0));
        }
        let mut last = std::collections::BTreeMap::new();
        last.insert(KeychainKind::External, 0);
        wallet
            .vault_wallet
            .apply_update(bdk_wallet::Update {
                tx_update: graph.into(),
                chain: Some(cp),
                last_active_indices: last,
            })
            .unwrap();
        ops
    }

    #[test]
    fn get_balance_excludes_inscribed_from_spendable() {
        let mut w = unified();
        let ops = fund(&mut w, &[(10_000, true), (50_000, true)]);
        w.inscribed_utxos.insert(ops[0]); // protect the 10k UTXO

        let bal = w.get_balance();
        assert_eq!(
            bal.total.confirmed.to_sat(),
            60_000,
            "raw total counts everything"
        );
        assert_eq!(
            bal.spendable.confirmed.to_sat(),
            50_000,
            "spendable excludes the inscribed UTXO"
        );
        assert_eq!(bal.inscribed, 10_000, "inscribed value = total - spendable");
    }

    #[test]
    fn get_balance_counts_unconfirmed_as_trusted_pending() {
        let mut w = unified();
        fund(&mut w, &[(30_000, false)]);

        let bal = w.get_balance();
        assert_eq!(bal.spendable.confirmed.to_sat(), 0);
        assert_eq!(bal.spendable.trusted_pending.to_sat(), 30_000);
    }

    #[test]
    fn reset_sync_state_rebuilds_empty_wallet() {
        let mut w = unified();
        fund(&mut w, &[(40_000, true)]);
        assert_eq!(w.get_balance().total.confirmed.to_sat(), 40_000);

        w.reset_sync_state().expect("reset");
        assert_eq!(
            w.get_balance().total.confirmed.to_sat(),
            0,
            "reset rebuilds wallets from descriptors, dropping synced txs"
        );
    }

    #[test]
    fn export_changeset_succeeds_for_funded_wallet() {
        let mut w = unified();
        fund(&mut w, &[(40_000, true)]);
        assert!(w.export_changeset().is_ok());
    }

    #[test]
    fn public_key_getters_return_valid_hex() {
        let w = unified();
        let tap = w.get_taproot_public_key(0).expect("taproot pubkey");
        assert!(hex::decode(&tap).is_ok(), "taproot pubkey is hex: {tap}");
        assert!(
            matches!(tap.len(), 64 | 66),
            "x-only/compressed pubkey hex: {tap}"
        );

        let dual = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Dual)
            .build()
            .unwrap();
        let pay = dual.get_payment_public_key(0).expect("payment pubkey");
        assert!(hex::decode(&pay).is_ok(), "payment pubkey is hex: {pay}");
    }

    #[test]
    fn pairing_secret_key_is_hex64() {
        let w = unified();
        let secret = w.get_pairing_secret_key_hex().expect("pairing secret");
        assert_eq!(secret.len(), 64);
        assert!(hex::decode(&secret).is_ok());
    }

    #[test]
    fn sign_message_signs_own_address_and_rejects_foreign() {
        let w = unified();
        let own = w.peek_taproot_address(0).to_string();
        assert!(
            w.sign_message(&own, "gm").is_ok(),
            "wallet signs its own address"
        );

        // A valid Regtest taproot address owned by a different seed must be rejected.
        let other = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let foreign = other.peek_taproot_address(0).to_string();
        assert!(
            w.sign_message(&foreign, "gm").is_err(),
            "cannot sign a foreign address"
        );
    }

    #[test]
    fn bip322_simple_signature_is_hex() {
        let w = unified();
        let own = w.peek_taproot_address(0).to_string();
        let sig = w
            .sign_bip322_simple_hex(&own, "hello bip322")
            .expect("bip322 sig");
        assert!(hex::decode(&sig).is_ok() && !sig.is_empty());
    }

    #[test]
    fn fresh_wallet_requires_full_scan_and_reveals_taproot_address() {
        let mut w = unified();
        assert!(w.needs_full_scan(), "fresh wallet needs a full scan");
        let addr = w.next_taproot_address().expect("address");
        assert_eq!(
            addr.address_type(),
            Some(bdk_wallet::bitcoin::AddressType::P2tr)
        );
    }

    #[test]
    fn prepare_requests_forces_full_scan_when_requested() {
        use crate::builder::SyncRequestType;
        let w = unified();
        let reqs = w.prepare_requests(true);
        assert!(matches!(reqs.taproot, SyncRequestType::Full(_)));
    }
}
