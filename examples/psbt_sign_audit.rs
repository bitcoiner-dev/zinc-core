use base64::Engine;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use std::collections::HashSet;
use std::str::FromStr;
use zinc_core::{Inscription, Network, Satpoint, WalletBuilder, ZincMnemonic};

const DEMO_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn build_demo_psbt(outpoint: OutPoint, input_sats: u64, output_sats: u64) -> Result<Psbt, String> {
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_sats),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| e.to_string())?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: ScriptBuf::new(),
    });

    Ok(psbt)
}

fn main() -> Result<(), String> {
    let mnemonic = ZincMnemonic::parse(DEMO_MNEMONIC).map_err(|e| e.to_string())?;
    let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic).build()?;

    let tracked_outpoint = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .map_err(|e| e.to_string())?,
        vout: 0,
    };

    let tracked_inscription = Inscription {
        id: "demo-inscription-i0".to_string(),
        number: 1,
        satpoint: Satpoint {
            outpoint: tracked_outpoint,
            offset: 9_999,
        },
        content_type: Some("text/plain".to_string()),
        value: Some(10_000),
        content_length: None,
        timestamp: None,
    };

    wallet.apply_verified_ordinals_update(
        vec![tracked_inscription],
        HashSet::from([tracked_outpoint]),
    );

    let psbt = build_demo_psbt(tracked_outpoint, 10_000, 9_999)?;
    let psbt_base64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

    let analysis_json = wallet.analyze_psbt(&psbt_base64)?;
    let analysis_value: serde_json::Value =
        serde_json::from_str(&analysis_json).map_err(|e| e.to_string())?;

    println!(
        "Ordinal Shield analysis:\n{}",
        serde_json::to_string_pretty(&analysis_value).map_err(|e| e.to_string())?
    );

    Ok(())
}
