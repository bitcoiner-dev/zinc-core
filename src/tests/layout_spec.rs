//! Layout derivation tests. Address fixtures are the canonical BIP-86/84/49/44
//! specification test vectors (mnemonic "abandon…about"), so every pinned
//! value is externally verifiable against the BIPs themselves.

use bdk_wallet::bitcoin::Network;

use crate::builder::{DerivationMode, PaymentAddressType, Seed64};
use crate::keys::ZincMnemonic;
use crate::layout::{derive_layout_addresses, BranchSpec, LayoutSpec, ScriptKind};

const SPEC_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn spec_seed() -> Seed64 {
    let mnemonic = ZincMnemonic::parse(SPEC_MNEMONIC).expect("spec mnemonic");
    Seed64::from_array(*mnemonic.to_seed(""))
}

fn layout(
    vault_purpose: u32,
    payment: Option<(u32, ScriptKind)>,
    mode: DerivationMode,
) -> LayoutSpec {
    LayoutSpec {
        vault: BranchSpec {
            purpose: vault_purpose,
            script: ScriptKind::Tr,
        },
        payment: payment.map(|(purpose, script)| BranchSpec { purpose, script }),
        derivation_mode: mode,
    }
}

#[test]
fn derives_bip86_and_bip84_spec_vectors() {
    let addresses = derive_layout_addresses(
        Network::Bitcoin,
        &spec_seed(),
        &LayoutSpec::zinc_default(),
        0,
        0,
        0,
        2,
    )
    .expect("derive");

    // BIP-86 test vectors, m/86'/0'/0'/0/0 and /0/1.
    assert_eq!(
        addresses.vault[0],
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    assert_eq!(
        addresses.vault[1],
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
    );
    // BIP-84 test vectors, m/84'/0'/0'/0/0 and /0/1.
    let payment = addresses.payment.expect("payment branch");
    assert_eq!(payment[0], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(payment[1], "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
}

#[test]
fn derives_bip49_and_bip44_payment_branches() {
    let nested = derive_layout_addresses(
        Network::Bitcoin,
        &spec_seed(),
        &layout(86, Some((49, ScriptKind::ShWpkh)), DerivationMode::Account),
        0,
        0,
        0,
        1,
    )
    .expect("derive nested");
    // BIP-49 test vector, m/49'/0'/0'/0/0.
    assert_eq!(
        nested.payment.expect("payment")[0],
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
    );

    let legacy = derive_layout_addresses(
        Network::Bitcoin,
        &spec_seed(),
        &layout(86, Some((44, ScriptKind::Pkh)), DerivationMode::Account),
        0,
        0,
        0,
        1,
    )
    .expect("derive legacy");
    // BIP-44 test vector, m/44'/0'/0'/0/0.
    assert_eq!(
        legacy.payment.expect("payment")[0],
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
    );
}

#[test]
fn index_mode_maps_logical_accounts_onto_account_zero() {
    let seed = spec_seed();
    let account_style = derive_layout_addresses(
        Network::Bitcoin,
        &seed,
        &LayoutSpec::zinc_default(),
        0,
        0,
        0,
        4,
    )
    .expect("account style");

    let index_layout = LayoutSpec {
        derivation_mode: DerivationMode::Index,
        ..LayoutSpec::zinc_default()
    };
    assert_eq!(index_layout.account_and_index(2), (0, 2));

    // Index mode: logical account N lives at account 0, address index N — the
    // derived branch must therefore be identical to account 0's address run.
    let index_style = derive_layout_addresses(Network::Bitcoin, &seed, &index_layout, 2, 0, 0, 4)
        .expect("index style");
    assert_eq!(index_style.vault, account_style.vault);

    // Account mode: logical account 1 derives a different account subtree.
    let account_one = derive_layout_addresses(
        Network::Bitcoin,
        &seed,
        &LayoutSpec::zinc_default(),
        1,
        0,
        0,
        1,
    )
    .expect("account 1");
    assert_ne!(account_one.vault[0], account_style.vault[0]);
}

#[test]
fn unified_layouts_have_no_payment_branch_and_testnet_coin_type_applies() {
    let unified = derive_layout_addresses(
        Network::Bitcoin,
        &spec_seed(),
        &layout(86, None, DerivationMode::Account),
        0,
        0,
        0,
        1,
    )
    .expect("unified");
    assert!(unified.payment.is_none());

    let regtest = derive_layout_addresses(
        Network::Regtest,
        &spec_seed(),
        &LayoutSpec::zinc_default(),
        0,
        0,
        0,
        1,
    )
    .expect("regtest");
    assert!(
        regtest.vault[0].starts_with("bcrt1p"),
        "coin type 1 + regtest hrp"
    );
    assert_ne!(regtest.vault[0], unified.vault[0]);
}

#[test]
fn validate_rejects_unrepresentable_layouts() {
    // Non-taproot ordinals branch.
    let bad_vault = LayoutSpec {
        vault: BranchSpec {
            purpose: 84,
            script: ScriptKind::Wpkh,
        },
        payment: None,
        derivation_mode: DerivationMode::Account,
    };
    assert!(bad_vault.validate().is_err());

    // Taproot payment branch (should be a unified layout instead).
    let bad_payment = layout(86, Some((86, ScriptKind::Tr)), DerivationMode::Account);
    assert!(bad_payment.validate().is_err());

    // Out-of-range purpose.
    let bad_purpose = layout(0x8000_0000, None, DerivationMode::Account);
    assert!(bad_purpose.validate().is_err());

    // derive_layout_addresses enforces validate() and the chain range.
    assert!(
        derive_layout_addresses(Network::Bitcoin, &spec_seed(), &bad_vault, 0, 0, 0, 1).is_err()
    );
    assert!(derive_layout_addresses(
        Network::Bitcoin,
        &spec_seed(),
        &LayoutSpec::zinc_default(),
        0,
        2,
        0,
        1
    )
    .is_err());
}

#[test]
fn implied_payment_type_matches_script_kind() {
    assert_eq!(
        LayoutSpec::zinc_default().implied_payment_address_type(),
        Some(PaymentAddressType::NativeSegwit)
    );
    assert_eq!(
        layout(86, Some((49, ScriptKind::ShWpkh)), DerivationMode::Account)
            .implied_payment_address_type(),
        Some(PaymentAddressType::NestedSegwit)
    );
    assert_eq!(
        layout(86, Some((44, ScriptKind::Pkh)), DerivationMode::Account)
            .implied_payment_address_type(),
        Some(PaymentAddressType::Legacy)
    );
    assert_eq!(
        layout(86, None, DerivationMode::Account).implied_payment_address_type(),
        None
    );
}

#[test]
fn with_layout_builds_wallets_matching_scan_derivation() {
    use crate::builder::WalletBuilder;

    // THE invariant discovery depends on: a wallet adopted via with_layout
    // must land on exactly the addresses the scan derived.
    let spec = layout(86, Some((49, ScriptKind::ShWpkh)), DerivationMode::Account);
    let scan = derive_layout_addresses(Network::Bitcoin, &spec_seed(), &spec, 1, 0, 0, 1)
        .expect("scan derivation");

    let wallet = WalletBuilder::from_seed(Network::Bitcoin, spec_seed())
        .with_account_index(1)
        .with_layout(spec)
        .expect("layout accepted")
        .build()
        .expect("build");
    assert_eq!(wallet.peek_taproot_address(0).to_string(), scan.vault[0]);
    assert_eq!(
        wallet.peek_payment_address(0).map(|a| a.to_string()),
        scan.payment.map(|p| p[0].clone()),
    );

    // Index-mode adoption: logical account 2 = account 0, address index 2.
    let index_spec = LayoutSpec {
        derivation_mode: DerivationMode::Index,
        ..LayoutSpec::zinc_default()
    };
    let index_scan =
        derive_layout_addresses(Network::Bitcoin, &spec_seed(), &index_spec, 2, 0, 0, 3)
            .expect("index scan");
    let index_wallet = WalletBuilder::from_seed(Network::Bitcoin, spec_seed())
        .with_account_index(2)
        .with_layout(index_spec)
        .expect("layout accepted")
        .build()
        .expect("build");
    // Peek(0) resolves to the active receive index (2 in Index mode).
    assert_eq!(
        index_wallet.peek_taproot_address(0).to_string(),
        index_scan.vault[2]
    );
}

#[test]
fn with_layout_rejects_non_seed_wallets_and_bad_layouts() {
    use crate::builder::WalletBuilder;

    let bad = LayoutSpec {
        vault: BranchSpec {
            purpose: 84,
            script: ScriptKind::Wpkh,
        },
        payment: None,
        derivation_mode: DerivationMode::Account,
    };
    assert!(WalletBuilder::from_seed(Network::Regtest, spec_seed())
        .with_layout(bad)
        .is_err());

    let regtest_taproot = derive_layout_addresses(
        Network::Regtest,
        &spec_seed(),
        &LayoutSpec::zinc_default(),
        0,
        0,
        0,
        1,
    )
    .expect("derive")
    .vault[0]
        .clone();
    let watch = WalletBuilder::from_watch_only(Network::Regtest)
        .with_layout(LayoutSpec::zinc_default())
        .expect("layout itself is valid")
        .with_watch_address(&regtest_taproot)
        .expect("address ok");
    // Non-seed kinds are rejected at build time.
    assert!(watch.build().is_err());
}

#[test]
fn layout_spec_serde_round_trips_with_wire_names() {
    let spec = layout(86, Some((49, ScriptKind::ShWpkh)), DerivationMode::Index);
    let json = serde_json::to_value(spec).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({
            "vault": { "purpose": 86, "script": "tr" },
            "payment": { "purpose": 49, "script": "sh-wpkh" },
            "derivationMode": "index"
        })
    );
    let back: LayoutSpec = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back, spec);
}
