use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_wallet::bitcoin::{
    absolute::LockTime, blockdata::constants::genesis_block, hashes::Hash, transaction::Version,
    Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxGraph};
use bdk_wallet::KeychainKind;

use crate::{
    ordinals::types::{Inscription, Satpoint},
    AddressScheme, CompanionRoutineDescriptorSlot, DerivationMode, Seed64, WalletBuilder,
    ZincWallet, MAX_COMPANION_ROUTINE_FACT_AGE_SECONDS,
};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn protected_preview_ids_are_phone_derived_canonical_sorted_and_capped() {
    let (mut wallet, outpoint, prevout) = funded_wallet(false, DerivationMode::Account, 0);
    let psbt = psbt(&wallet, outpoint, prevout, false);
    let mut inscriptions = Vec::new();
    let mut protected = std::collections::HashSet::new();
    for (position, prefix) in ['d', 'a', 'c', 'b'].into_iter().enumerate() {
        let protected_outpoint = OutPoint::new(
            bitcoin::Txid::from_byte_array([u8::try_from(position + 20).unwrap(); 32]),
            0,
        );
        protected.insert(protected_outpoint);
        inscriptions.push(Inscription {
            id: format!("{}i0", prefix.to_string().repeat(64)),
            number: i64::try_from(position).unwrap(),
            satpoint: Satpoint {
                outpoint: protected_outpoint,
                offset: 0,
            },
            content_type: Some("image/png".to_string()),
            value: Some(10_000),
            content_length: Some(128),
            timestamp: Some(now_unix()),
        });
    }
    inscriptions.push(Inscription {
        id: format!("{}i00", "e".repeat(64)),
        number: 5,
        satpoint: Satpoint {
            outpoint: *protected.iter().next().unwrap(),
            offset: 0,
        },
        content_type: Some("image/png".to_string()),
        value: Some(10_000),
        content_length: Some(128),
        timestamp: Some(now_unix()),
    });
    wallet
        .apply_verified_ordinals_update(
            inscriptions,
            protected,
            vec![],
            std::collections::HashSet::from([outpoint]),
            wallet.chain_state_generation(),
        )
        .unwrap();

    let snapshot = wallet.companion_routine_wallet_snapshot(0, &psbt).unwrap();
    assert_eq!(
        snapshot.protected_preview_ids(),
        &[
            format!("{}i0", "a".repeat(64)),
            format!("{}i0", "b".repeat(64)),
            format!("{}i0", "c".repeat(64)),
        ]
    );
}

fn funded_wallet(
    payment: bool,
    derivation_mode: DerivationMode,
    account_index: u32,
) -> (ZincWallet, OutPoint, TxOut) {
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([7; 64]))
        .with_scheme(AddressScheme::Dual)
        .with_derivation_mode(derivation_mode)
        .with_account_index(account_index)
        .build()
        .unwrap();
    let address = if payment {
        wallet
            .payment_wallet
            .as_mut()
            .unwrap()
            .reveal_next_address(KeychainKind::External)
            .address
    } else {
        wallet
            .vault_wallet
            .reveal_next_address(KeychainKind::External)
            .address
    };
    let funding_output = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: address.script_pubkey(),
    };
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([9; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![funding_output.clone()],
    };
    let txid = funding.compute_txid();
    let tip_hash = BlockHash::from_byte_array([3; 32]);
    let anchor = BlockId {
        height: 100,
        hash: tip_hash,
    };
    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let _ = graph.insert_tx(funding);
    let _ = graph.insert_anchor(
        txid,
        ConfirmationBlockTime {
            block_id: anchor,
            confirmation_time: 1_000,
        },
    );
    let genesis = BlockId {
        height: 0,
        hash: genesis_block(Network::Regtest).block_hash(),
    };
    let chain = CheckPoint::from_block_ids([genesis, anchor]).unwrap();
    let funded_update = bdk_wallet::Update {
        tx_update: graph.into(),
        chain: Some(chain.clone()),
        last_active_indices: BTreeMap::from([(KeychainKind::External, 0)]),
    };
    let empty_update = bdk_wallet::Update {
        tx_update: Default::default(),
        chain: Some(chain),
        last_active_indices: BTreeMap::new(),
    };
    if payment {
        wallet
            .apply_sync(empty_update, Some(funded_update))
            .unwrap();
    } else {
        wallet
            .apply_sync(funded_update, Some(empty_update))
            .unwrap();
    }
    wallet.mark_current_wallet_outpoints_classified_for_test();
    (wallet, OutPoint::new(txid, 0), funding_output)
}

#[test]
fn incomplete_dual_sync_cannot_refresh_companion_facts() {
    let (mut wallet, outpoint, prevout) = funded_wallet(false, DerivationMode::Account, 0);
    let psbt = psbt(&wallet, outpoint, prevout, false);
    let update = bdk_wallet::Update {
        tx_update: Default::default(),
        chain: None,
        last_active_indices: BTreeMap::new(),
    };

    assert!(wallet
        .apply_sync(update, None::<bdk_wallet::Update>)
        .is_err());
    assert!(wallet.chain_observed_at_unix.is_none());
    assert!(wallet.companion_routine_wallet_snapshot(0, &psbt).is_err());
}

#[test]
fn oversized_or_duplicate_input_shapes_fail_before_wallet_fact_lookup() {
    let (wallet, outpoint, prevout) = funded_wallet(false, DerivationMode::Account, 0);
    let canonical = psbt(&wallet, outpoint, prevout, false);
    let mut duplicate = bitcoin::Psbt::deserialize(&canonical).unwrap();
    duplicate
        .unsigned_tx
        .input
        .push(duplicate.unsigned_tx.input[0].clone());
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert!(wallet
        .companion_routine_wallet_snapshot(0, &duplicate.serialize())
        .is_err());

    let mut oversized = bitcoin::Psbt::deserialize(&canonical).unwrap();
    for suffix in 1..=256u32 {
        let mut input = oversized.unsigned_tx.input[0].clone();
        input.previous_output = OutPoint::new(
            bitcoin::Txid::from_byte_array([u8::try_from(suffix % 255).unwrap(); 32]),
            suffix,
        );
        oversized.unsigned_tx.input.push(input);
        oversized.inputs.push(oversized.inputs[0].clone());
    }
    assert!(wallet
        .companion_routine_wallet_snapshot(0, &oversized.serialize())
        .is_err());
}

fn psbt(wallet: &ZincWallet, outpoint: OutPoint, prevout: TxOut, payment: bool) -> Vec<u8> {
    let recipient = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([8; 64]))
        .build()
        .unwrap()
        .peek_taproot_address(0);
    let change = if payment {
        wallet
            .payment_wallet
            .as_ref()
            .unwrap()
            .peek_address(KeychainKind::Internal, 0)
            .address
    } else {
        wallet
            .vault_wallet
            .peek_address(KeychainKind::Internal, 0)
            .address
    };
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: recipient.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(39_000),
                script_pubkey: change.script_pubkey(),
            },
        ],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(transaction).unwrap();
    psbt.inputs[0].witness_utxo = Some(prevout);
    psbt.serialize()
}

#[test]
fn snapshot_is_minted_only_from_fresh_clean_active_wallet_state() {
    let (mut wallet, outpoint, prevout) = funded_wallet(false, DerivationMode::Account, 0);
    let psbt = psbt(&wallet, outpoint, prevout, false);
    let snapshot = wallet.companion_routine_wallet_snapshot(0, &psbt).unwrap();
    assert_eq!(snapshot.inputs().len(), 1);
    assert_eq!(snapshot.inputs()[0].outpoint(), outpoint);
    assert!(snapshot.inputs()[0].slot() == CompanionRoutineDescriptorSlot::TaprootExternal);
    assert_eq!(snapshot.change_outputs().len(), 1);
    assert!(snapshot.change_outputs()[0].slot() == CompanionRoutineDescriptorSlot::TaprootInternal);
    assert_eq!(snapshot.chain_state_generation(), 1);

    wallet.chain_observed_at_unix = Some(
        now_unix()
            .saturating_sub(MAX_COMPANION_ROUTINE_FACT_AGE_SECONDS)
            .saturating_sub(1),
    );
    assert!(wallet.companion_routine_wallet_snapshot(0, &psbt).is_err());
    wallet.chain_observed_at_unix = Some(now_unix());
    wallet.inscribed_utxos.insert(outpoint);
    assert!(wallet.companion_routine_wallet_snapshot(0, &psbt).is_err());
    assert!(wallet.companion_routine_wallet_snapshot(1, &psbt).is_err());
}

#[test]
fn snapshot_maps_bip84_and_index_mode_to_companion_slots() {
    let (payment_wallet, payment_outpoint, payment_prevout) =
        funded_wallet(true, DerivationMode::Account, 0);
    let payment_psbt = psbt(&payment_wallet, payment_outpoint, payment_prevout, true);
    let payment = payment_wallet
        .companion_routine_wallet_snapshot(0, &payment_psbt)
        .unwrap();
    assert!(payment.inputs()[0].slot() == CompanionRoutineDescriptorSlot::PaymentExternal);
    assert!(payment.change_outputs()[0].slot() == CompanionRoutineDescriptorSlot::PaymentInternal);
    assert_eq!(payment.inputs()[0].derivation_index(), 1);

    let (index_wallet, index_outpoint, index_prevout) =
        funded_wallet(false, DerivationMode::Index, 5);
    let index_psbt = psbt(&index_wallet, index_outpoint, index_prevout, false);
    let index = index_wallet
        .companion_routine_wallet_snapshot(5, &index_psbt)
        .unwrap();
    assert_eq!(index.inputs()[0].derivation_index(), 5);
    assert_eq!(index.change_outputs()[0].derivation_index(), 5);
}
