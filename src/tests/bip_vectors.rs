//! Known-answer BIP test vectors + a differential derivation check (wallet plan 023, Phase 1 / L1).
//!
//! These pin the wallet's key-derivation foundation to the *published* BIP specifications, so an
//! accidental change in seed derivation, HD child derivation, or the Taproot output-key tweak is
//! caught as a legible failure rather than silently producing a different (unrecoverable) wallet.
//! Every constant below is copied verbatim from the canonical spec text:
//!
//! - **BIP-39** seeds — <https://github.com/trezor/python-mnemonic> `vectors.json` (passphrase
//!   `"TREZOR"`). The empty-passphrase seed is separately locked in `keys/mnemonic.rs`.
//! - **BIP-32** extended keys — test vector 1, <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
//! - **BIP-86** Taproot addresses — <https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki>.
//!
//! The differential test derives the same Taproot script two independent ways — through zinc-core's
//! BDK/miniscript descriptor path, and through raw `rust-bitcoin` bip32 + `ScriptBuf::new_p2tr` —
//! and asserts they agree, so the descriptor abstraction can never drift from the primitive it is
//! built on. Pure computation, no file I/O, so (unlike `golden_psbt`) it is not wasm-gated.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::format_collect)]

use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use bdk_wallet::bitcoin::{Network, ScriptBuf};

use crate::keys::{taproot_descriptors, ZincMnemonic};

/// Canonical BIP-39 / BIP-86 mnemonic (all-zero entropy).
const ABANDON_ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// BIP-39: mnemonic + passphrase "TREZOR" → 512-bit seed, for two spec vectors. This locks the
/// PBKDF2 passphrase-salting path that the empty-passphrase test in `keys/mnemonic.rs` does not.
#[test]
fn bip39_seed_matches_trezor_passphrase_vectors() {
    let cases = [
        (
            ABANDON_ABOUT,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
    ];
    for (phrase, expected_seed) in cases {
        let m = ZincMnemonic::parse(phrase).unwrap();
        let seed = m.to_seed("TREZOR");
        assert_eq!(to_hex(&seed[..]), expected_seed, "BIP-39 seed mismatch for: {phrase}");
    }
}

/// BIP-32 test vector 1 (seed `000102030405060708090a0b0c0d0e0f`): master + two child chains,
/// extended private and public keys. Pins the HD derivation core BIP-86 is built on, including
/// hardened (`0'`) and normal (`1`) derivation.
#[test]
fn bip32_test_vector_1_master_and_children() {
    let secp = Secp256k1::new();
    // 000102...0f as raw bytes.
    let seed: Vec<u8> = (0u8..=15).collect();
    let master = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

    // (derivation path from master, expected xprv, expected xpub)
    let cases = [
        (
            "m",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        ),
        (
            "0'",
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        ),
        (
            "0'/1",
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        ),
    ];

    for (path, expected_xprv, expected_xpub) in cases {
        let xprv = if path == "m" {
            master
        } else {
            let dp = DerivationPath::from_str(path).unwrap();
            master.derive_priv(&secp, &dp).unwrap()
        };
        let xpub = Xpub::from_priv(&secp, &xprv);
        assert_eq!(xprv.to_string(), expected_xprv, "BIP-32 xprv mismatch at m/{path}");
        assert_eq!(xpub.to_string(), expected_xpub, "BIP-32 xpub mismatch at m/{path}");
    }
}

/// BIP-86: the first two receiving addresses and the first change address, derived through
/// zinc-core's actual `taproot_descriptors` (BDK `Bip86` template) on mainnet, must equal the
/// spec's addresses. This locks the whole path: account derivation → child key → x-only output
/// key tweak → bech32m (`bc1p…`) encoding.
#[test]
fn bip86_receive_and_change_addresses_match_spec() {
    let m = ZincMnemonic::parse(ABANDON_ABOUT).unwrap();
    let desc = taproot_descriptors(&m, Network::Bitcoin).unwrap();

    let external0 = desc
        .external
        .at_derivation_index(0)
        .unwrap()
        .address(Network::Bitcoin)
        .unwrap();
    let external1 = desc
        .external
        .at_derivation_index(1)
        .unwrap()
        .address(Network::Bitcoin)
        .unwrap();
    let internal0 = desc
        .internal
        .at_derivation_index(0)
        .unwrap()
        .address(Network::Bitcoin)
        .unwrap();

    assert_eq!(
        external0.to_string(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        "BIP-86 m/86'/0'/0'/0/0"
    );
    assert_eq!(
        external1.to_string(),
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
        "BIP-86 m/86'/0'/0'/0/1"
    );
    assert_eq!(
        internal0.to_string(),
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        "BIP-86 m/86'/0'/0'/1/0 (change)"
    );
}

/// Differential: for several receive indices, the script produced by zinc-core's descriptor must
/// byte-match a Taproot script derived independently from raw `rust-bitcoin` bip32 primitives plus
/// `ScriptBuf::new_p2tr` (key-path only, no merkle root = BIP-86). Index 0 is additionally checked
/// against the spec scriptPubKey, so the two derivation paths are pinned to an external ground
/// truth, not just to each other.
#[test]
fn taproot_derivation_matches_raw_rust_bitcoin_differential() {
    let secp = Secp256k1::new();
    let m = ZincMnemonic::parse(ABANDON_ABOUT).unwrap();
    let desc = taproot_descriptors(&m, Network::Bitcoin).unwrap();

    let seed = m.to_seed("");
    let master = Xpriv::new_master(Network::Bitcoin, &seed[..]).unwrap();

    for i in 0u32..4 {
        // zinc-core: descriptor → definite → scriptPubKey.
        let zinc_spk = desc.external.at_derivation_index(i).unwrap().script_pubkey();

        // Raw rust-bitcoin: derive m/86'/0'/0'/0/i, tweak the x-only key into a p2tr output.
        let dp = DerivationPath::from_str(&format!("86'/0'/0'/0/{i}")).unwrap();
        let child = master.derive_priv(&secp, &dp).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &child.private_key);
        let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let raw_spk = ScriptBuf::new_p2tr(&secp, internal_key, None);

        assert_eq!(
            zinc_spk, raw_spk,
            "descriptor vs raw taproot derivation diverged at index {i}"
        );
    }

    // External ground truth: index 0 equals the BIP-86 spec scriptPubKey.
    let spk0 = desc.external.at_derivation_index(0).unwrap().script_pubkey();
    assert_eq!(
        to_hex(spk0.as_bytes()),
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        "BIP-86 first-receive scriptPubKey"
    );
}
