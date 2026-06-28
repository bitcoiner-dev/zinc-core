//! Coverage for watch-only / xpub-import construction paths in `builder.rs`, reached through the
//! public `WalletBuilder` API: `with_watch_address` (taproot-only validation, network match),
//! `with_xpub` → `parse_extended_public_key` (ypub/zpub/tpub version normalization, bad prefixes),
//! and `get_accounts` seed enumeration.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::builder::{AddressScheme, Seed64, WalletBuilder};
    use bdk_wallet::bitcoin::{base58, Network};

    // BIP-86 account-0 xpub + first taproot receive address for the canonical "abandon ... about" seed.
    const MAINNET_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
    const MAINNET_TR_ADDR: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    /// Re-encode a base58check extended key under a different 4-byte version prefix.
    fn reversion(xpub: &str, version: [u8; 4]) -> String {
        let mut data = base58::decode_check(xpub).unwrap();
        data[0..4].copy_from_slice(&version);
        base58::encode_check(&data)
    }

    // ---------- with_watch_address ----------

    #[test]
    fn watch_address_rejects_invalid_string() {
        let err = WalletBuilder::from_watch_only(Network::Regtest)
            .with_watch_address("not-an-address")
            .err()
            .unwrap();
        assert!(err.contains("Invalid address"), "{err}");
    }

    #[test]
    fn watch_address_rejects_network_mismatch() {
        // A valid mainnet taproot address rejected by a Regtest builder.
        let err = WalletBuilder::from_watch_only(Network::Regtest)
            .with_watch_address(MAINNET_TR_ADDR)
            .err()
            .unwrap();
        assert!(err.contains("Network mismatch"), "{err}");
    }

    #[test]
    fn watch_address_rejects_non_taproot() {
        // Source a valid Regtest non-taproot (wpkh) address from a dual-scheme wallet.
        let dual = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Dual)
            .build()
            .unwrap();
        let pay = dual.peek_payment_address(0).unwrap().to_string();
        let err = WalletBuilder::from_watch_only(Network::Regtest)
            .with_watch_address(&pay)
            .err()
            .unwrap();
        assert!(err.contains("taproot"), "{err}");
    }

    #[test]
    fn watch_address_accepts_taproot_and_round_trips() {
        let seed_wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([1u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let tr_addr = seed_wallet.peek_taproot_address(0).to_string();

        let watch = WalletBuilder::from_watch_only(Network::Regtest)
            .with_watch_address(&tr_addr)
            .unwrap()
            .build()
            .unwrap();
        // Building from the taproot address exercises taproot_output_key_from_address; the watch
        // wallet must derive the same address back.
        assert_eq!(watch.peek_taproot_address(0).to_string(), tr_addr);
    }

    // ---------- with_xpub → parse_extended_public_key ----------

    #[test]
    fn xpub_accepts_zpub_via_version_normalization() {
        // Mainnet zpub version is normalized back to xpub before decoding.
        let zpub = reversion(MAINNET_XPUB, [0x04, 0xB2, 0x47, 0x46]);
        assert!(WalletBuilder::from_watch_only(Network::Bitcoin)
            .with_xpub(&zpub)
            .is_ok());
    }

    #[test]
    fn xpub_accepts_tpub_via_version_normalization() {
        // Mainnet payload re-tagged as a testnet vpub still normalizes and decodes.
        let vpub = reversion(MAINNET_XPUB, [0x04, 0x5F, 0x1C, 0xF6]);
        assert!(WalletBuilder::from_watch_only(Network::Testnet)
            .with_xpub(&vpub)
            .is_ok());
    }

    #[test]
    fn xpub_rejects_unsupported_prefix() {
        let bad = reversion(MAINNET_XPUB, [0x01, 0x02, 0x03, 0x04]);
        let err = WalletBuilder::from_watch_only(Network::Bitcoin)
            .with_xpub(&bad)
            .err()
            .unwrap();
        assert!(err.contains("Unsupported extended public key prefix"), "{err}");
    }

    #[test]
    fn xpub_rejects_garbage() {
        let err = WalletBuilder::from_watch_only(Network::Bitcoin)
            .with_xpub("definitely not a key")
            .err()
            .unwrap();
        assert!(err.contains("Invalid extended public key"), "{err}");
    }

    // ---------- get_accounts ----------

    #[test]
    fn get_accounts_enumerates_distinct_seed_accounts() {
        let w = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([0u8; 64]))
            .with_scheme(AddressScheme::Unified)
            .build()
            .unwrap();
        let accounts = w.get_accounts(3);
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].index, 0);
        assert_eq!(accounts[2].index, 2);
        assert_ne!(accounts[0].taproot_address, accounts[1].taproot_address);
        assert_ne!(accounts[1].taproot_address, accounts[2].taproot_address);
    }
}
