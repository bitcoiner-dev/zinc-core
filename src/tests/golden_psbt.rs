//! Golden-file tests for deterministic PSBT construction (wallet plan 023, Phase 1 / L1).
//!
//! For a fixed (seed, UTXO set, request) the **deterministic** planners — `plan_send_with_
//! salvage_tx`, `plan_consolidate_tx`, `plan_salvage_tx` — produce a byte-identical unsigned
//! transaction every run: inputs come from an explicit outpoint list (no BDK coin selection),
//! ordering is stable, outputs are placed deterministically, and locktime is fixed at zero.
//! (The BDK `create_psbt_tx` path is *not* deterministic — `TxOrdering::Shuffle` +
//! `SingleRandomDraw` — and is deliberately not exercised here.)
//!
//! Each scenario is snapshotted to a committed JSON golden. A change in coin selection,
//! output ordering, change handling, or fee arithmetic shows up as a readable diff. Update
//! the goldens intentionally after such a change with:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test -p zinc-core golden_psbt
//! ```
//!
//! Native only: the harness reads and writes golden files, which wasm cannot do. The module
//! is gated out for `wasm32` in `tests/mod.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{
    Address, Amount, BlockHash, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut,
    Txid,
};
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxGraph};
use bdk_wallet::KeychainKind;
use bitcoin::psbt::Psbt;
use serde_json::json;

use crate::builder::{
    fee_rate_from_sat_per_vb_f64, AddressScheme, Seed64, WalletBuilder, ZincWallet,
};

/// A deterministic funding UTXO with a fixed txid derived from `uid`.
fn dummy_tx(value: u64, script_pubkey: ScriptBuf, uid: u8) -> Transaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[31] = uid;
    let txid = Txid::from_byte_array(hash_bytes);
    Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![bdk_wallet::bitcoin::TxIn {
            previous_output: OutPoint::new(txid, 0),
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

/// A Regtest unified-scheme wallet from the all-zero seed, funded with one confirmed UTXO
/// per entry in `values`, with the ordinals safety lock cleared so the planners run.
/// Returns the wallet, its receive address, the outpoints (in `values` order), and the
/// total funded value (for fee computation).
fn funded_wallet(values: &[u64]) -> (ZincWallet, Address, Vec<OutPoint>, u64) {
    let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
        .with_scheme(AddressScheme::Unified)
        .build()
        .unwrap();
    let addr = wallet
        .vault_wallet
        .reveal_next_address(KeychainKind::External)
        .address;
    let spk = addr.script_pubkey();

    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let hash = BlockHash::all_zeros();
    let mut ops = Vec::new();
    for (i, &v) in values.iter().enumerate() {
        let tx = dummy_tx(v, spk.clone(), u8::try_from(i).unwrap() + 1);
        let _ = graph.insert_tx(tx.clone());
        let _ = graph.insert_anchor(
            tx.compute_txid(),
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 100 + u32::try_from(i).unwrap(),
                    hash,
                },
                confirmation_time: 1000 + u64::try_from(i).unwrap(),
            },
        );
        ops.push(OutPoint::new(tx.compute_txid(), 0));
    }
    let mut last = BTreeMap::new();
    last.insert(KeychainKind::External, 0);
    wallet
        .vault_wallet
        .apply_update(bdk_wallet::Update {
            tx_update: graph.into(),
            chain: None,
            last_active_indices: last,
        })
        .unwrap();

    // Clear the ordinals safety lock (no inscriptions, nothing protected, no runes) so the
    // planners are willing to build. This is the sanctioned test bypass.
    wallet.apply_verified_ordinals_update(vec![], HashSet::new(), vec![]);

    (wallet, addr, ops, values.iter().sum())
}

fn script_kind(spk: &Script) -> &'static str {
    if spk.is_p2tr() {
        "p2tr"
    } else if spk.is_p2wpkh() {
        "p2wpkh"
    } else if spk.is_p2wsh() {
        "p2wsh"
    } else if spk.is_p2pkh() {
        "p2pkh"
    } else if spk.is_p2sh() {
        "p2sh"
    } else if spk.is_op_return() {
        "op_return"
    } else {
        "other"
    }
}

/// A readable, byte-exact snapshot of an unsigned transaction. The structured fields make a
/// diff legible; `unsigned_tx_hex` + `unsigned_txid` pin it to the exact bytes.
fn snapshot(psbt: &Psbt, total_in_sat: u64) -> serde_json::Value {
    let tx = &psbt.unsigned_tx;

    let inputs: Vec<serde_json::Value> = tx
        .input
        .iter()
        .map(|txin| json!({ "prevout": txin.previous_output.to_string() }))
        .collect();

    let mut total_out = 0u64;
    let outputs: Vec<serde_json::Value> = tx
        .output
        .iter()
        .map(|txout| {
            total_out += txout.value.to_sat();
            json!({
                "value_sat": txout.value.to_sat(),
                "kind": script_kind(&txout.script_pubkey),
                "script_pubkey_hex": hex::encode(txout.script_pubkey.as_bytes()),
            })
        })
        .collect();

    json!({
        "version": tx.version.0,
        "lock_time": tx.lock_time.to_consensus_u32(),
        "inputs": inputs,
        "outputs": outputs,
        "fee_sat": total_in_sat - total_out,
        "vsize": tx.vsize(),
        "weight": tx.weight().to_wu(),
        "unsigned_txid": tx.compute_txid().to_string(),
        "unsigned_tx_hex": bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx),
    })
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/tests/golden")
        .join(format!("{name}.json"))
}

/// Compare `actual` against the committed golden for `name`. Writes the golden when it is
/// missing or when `UPDATE_GOLDEN` is set; otherwise asserts equality with a readable diff.
fn check_golden(name: &str, actual: &serde_json::Value) {
    let path = golden_path(name);
    let pretty = serde_json::to_string_pretty(actual).unwrap();

    let write = |reason: &str| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{pretty}\n")).unwrap();
        reason.to_string()
    };

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        write("refreshed");
        return;
    }
    if !path.exists() {
        write("created");
        panic!(
            "golden {name} did not exist and was created at {}. Re-run to verify, then commit it.",
            path.display()
        );
    }

    let expected = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        expected.trim_end(),
        pretty,
        "\ngolden mismatch for {name}. If this change is intended, refresh it with:\n  \
         UPDATE_GOLDEN=1 cargo test -p zinc-core golden_psbt\n"
    );
}

/// A recipient address distinct from the wallet's own receive/change script, derived
/// deterministically as the next external address of the same fixed-seed wallet. Keeps
/// recipient vs. change visibly separate in the snapshot without hardcoding an address.
fn distinct_recipient(wallet: &mut ZincWallet) -> Address {
    wallet
        .vault_wallet
        .reveal_next_address(KeychainKind::External)
        .address
}

#[test]
fn send_to_recipient_one_sat_per_vb() {
    let (mut wallet, own, ops, total_in) = funded_wallet(&[50_000]);
    let recipient = distinct_recipient(&mut wallet);
    let psbt = wallet
        .plan_send_with_salvage_tx(
            &ops,
            &recipient,
            20_000,
            FeeRate::from_sat_per_vb(1).unwrap(),
            546,
            &own,
            &own,
        )
        .unwrap();
    check_golden("send_20k_1sat", &snapshot(&psbt, total_in));
}

#[test]
fn send_at_fractional_fee_rate() {
    // 1.5 sat/vB — exercises the fractional fee-rate arithmetic. A change to the fee-rate
    // rounding or the vsize estimate moves the change output and fails this golden.
    let (mut wallet, own, ops, total_in) = funded_wallet(&[50_000]);
    let recipient = distinct_recipient(&mut wallet);
    let psbt = wallet
        .plan_send_with_salvage_tx(
            &ops,
            &recipient,
            20_000,
            fee_rate_from_sat_per_vb_f64(1.5).unwrap(),
            546,
            &own,
            &own,
        )
        .unwrap();
    check_golden("send_20k_1_5sat", &snapshot(&psbt, total_in));
}

#[test]
fn consolidate_three_utxos() {
    let (wallet, own, ops, total_in) = funded_wallet(&[10_000, 20_000, 30_000]);
    let psbt = wallet
        .plan_consolidate_tx(&ops, FeeRate::from_sat_per_vb(2).unwrap(), &own)
        .unwrap();
    check_golden("consolidate_3_utxos_2sat", &snapshot(&psbt, total_in));
}
