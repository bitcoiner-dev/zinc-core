//! Descriptor ownership, not a UI filter, isolates indexed accounts.
use crate::builder::{
    AddressScheme, CreatePsbtRequest, DerivationMode, PaymentAddressType, Seed64, SignOptions,
    WalletBuilder, ZincWallet,
};
use base64::Engine;
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
};

fn account(index: u32, payment: PaymentAddressType) -> ZincWallet {
    WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
        .with_scheme(AddressScheme::Dual)
        .with_derivation_mode(DerivationMode::Index)
        .with_payment_address_type(payment)
        .with_account_index(index)
        .build()
        .unwrap()
}

fn receive(wallet: &Wallet, chain: KeychainKind, index: u32) -> ScriptBuf {
    wallet.peek_address(chain, index).script_pubkey()
}

fn apply(wallet: &mut Wallet, tx: &Transaction) {
    wallet.apply_unconfirmed_txs([(tx.clone(), 123)]);
}

#[test]
fn sibling_outputs_cannot_be_reported_selected_or_signed_after_reload() {
    for payment in [
        PaymentAddressType::NativeSegwit,
        PaymentAddressType::NestedSegwit,
        PaymentAddressType::Legacy,
    ] {
        // This wildcard account is the independent address oracle: indexed
        // account N must own exactly child N on each of its two chains.
        let oracle = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
            .with_scheme(AddressScheme::Dual)
            .with_payment_address_type(payment)
            .build()
            .unwrap();
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([3; 32]), 0),
                ..Default::default()
            }],
            output: (0..3)
                .flat_map(|index| {
                    [KeychainKind::External, KeychainKind::Internal]
                        .into_iter()
                        .flat_map(move |chain| [(index, chain, false), (index, chain, true)])
                })
                .map(|(index, chain, payment)| TxOut {
                    value: Amount::from_sat(100_000 + u64::from(index) * 10_000),
                    script_pubkey: receive(
                        if payment {
                            oracle.payment_wallet.as_ref().unwrap()
                        } else {
                            &oracle.vault_wallet
                        },
                        chain,
                        index,
                    ),
                })
                .collect(),
        };
        let mut ownership = std::collections::HashSet::new();
        for index in 0..3 {
            let mut wallet = account(index, payment);
            for branch in [
                &mut wallet.vault_wallet,
                wallet.payment_wallet.as_mut().unwrap(),
            ] {
                branch
                    .reveal_addresses_to(KeychainKind::Internal, 0)
                    .for_each(drop);
                apply(branch, &funding);
                assert!(!branch
                    .public_descriptor(KeychainKind::External)
                    .has_wildcard());
                let mut scan = branch.start_full_scan_at(123).build();
                for chain in [KeychainKind::External, KeychainKind::Internal] {
                    let scripts: Vec<_> = scan.iter_spks(chain).take(3).collect();
                    assert_eq!(
                        scripts.len(),
                        1,
                        "full scan must stop at this account's one key"
                    );
                }
            }
            let snapshot = wallet.export_changeset().unwrap();
            let mut wallet =
                WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([42; 64]))
                    .with_scheme(AddressScheme::Dual)
                    .with_derivation_mode(DerivationMode::Index)
                    .with_account_index(index)
                    .with_payment_address_type(payment)
                    .persistence(snapshot)
                    .build()
                    .unwrap();
            let outputs: Vec<_> = wallet
                .vault_wallet
                .list_unspent()
                .chain(wallet.payment_wallet.as_ref().unwrap().list_unspent())
                .collect();
            assert_eq!(outputs.len(), 4);
            for output in &outputs {
                assert_eq!(
                    output.txout.value.to_sat(),
                    100_000 + u64::from(index) * 10_000
                );
                assert!(
                    ownership.insert(output.outpoint),
                    "duplicate ownership across accounts"
                );
            }
            let classified = outputs.iter().map(|u| u.outpoint).collect();
            wallet
                .apply_verified_ordinals_update(
                    vec![],
                    Default::default(),
                    vec![],
                    classified,
                    wallet.chain_state_generation(),
                )
                .unwrap();
            let recipient =
                WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([43; 64]))
                    .build()
                    .unwrap()
                    .peek_taproot_address(0);
            let request =
                CreatePsbtRequest::from_parts(&recipient.to_string(), 40_000, 1.0).unwrap();
            let psbt = wallet.create_psbt_tx(&request).unwrap();
            assert!(psbt.unsigned_tx.input.iter().all(|input| outputs
                .iter()
                .any(|owned| owned.outpoint == input.previous_output)));
            let encoded = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
            let signed = wallet
                .sign_psbt(
                    &encoded,
                    Some(SignOptions {
                        finalize: true,
                        ..Default::default()
                    }),
                )
                .unwrap();
            let signed = bitcoin::psbt::Psbt::deserialize(
                &base64::engine::general_purpose::STANDARD
                    .decode(signed)
                    .unwrap(),
            )
            .unwrap();
            assert!(signed
                .inputs
                .iter()
                .all(|input| input.final_script_sig.is_some()
                    || input.final_script_witness.is_some()));
        }
        assert_eq!(
            ownership.len(),
            funding.output.len(),
            "all funded scripts recovered exactly once"
        );
    }
}
