//! Descriptor derivation for Taproot (BIP-86)

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::descriptor::template::Bip86;
use bdk_wallet::descriptor::{Descriptor, DescriptorPublicKey, IntoWalletDescriptor};
use bdk_wallet::KeychainKind;

use crate::error::ZincError;
use crate::keys::ZincMnemonic;

/// A pair of external (receive) and internal (change) descriptors.
pub struct DescriptorPair {
    /// External/receiving descriptor.
    pub external: Descriptor<DescriptorPublicKey>,
    /// Internal/change descriptor.
    pub internal: Descriptor<DescriptorPublicKey>,
}

/// Create BIP-86 Taproot descriptors from a mnemonic.
///
/// BIP-86 is the standard for single-key Taproot wallets,
/// using derivation path m/86'/0'/0' (or m/86'/1'/0' for testnet).
pub fn taproot_descriptors(
    mnemonic: &ZincMnemonic,
    network: Network,
) -> Result<DescriptorPair, ZincError> {
    let seed = mnemonic.to_seed("");
    let xprv =
        Xpriv::new_master(network, &*seed).map_err(|e| ZincError::KeyDerivation(e.to_string()))?;

    let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::new();

    let (external, _) = Bip86(xprv, KeychainKind::External)
        .into_wallet_descriptor(&secp, network)
        .map_err(|e| ZincError::KeyDerivation(e.to_string()))?;

    let (internal, _) = Bip86(xprv, KeychainKind::Internal)
        .into_wallet_descriptor(&secp, network)
        .map_err(|e| ZincError::KeyDerivation(e.to_string()))?;

    Ok(DescriptorPair { external, internal })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_taproot_descriptor_signet() {
        let m = ZincMnemonic::parse(TEST_MNEMONIC).unwrap();
        let desc = taproot_descriptors(&m, Network::Signet).unwrap();

        let external_str = desc.external.to_string();
        assert!(
            external_str.starts_with("tr("),
            "Expected Taproot descriptor, got: {external_str}"
        );
    }

    #[test]
    fn derive_taproot_descriptor_mainnet() {
        let m = ZincMnemonic::parse(TEST_MNEMONIC).unwrap();
        let desc = taproot_descriptors(&m, Network::Bitcoin).unwrap();

        let external_str = desc.external.to_string();
        assert!(external_str.starts_with("tr("));
    }

    #[test]
    fn external_and_internal_differ() {
        let m = ZincMnemonic::parse(TEST_MNEMONIC).unwrap();
        let desc = taproot_descriptors(&m, Network::Signet).unwrap();

        let external_str = desc.external.to_string();
        let internal_str = desc.internal.to_string();
        assert_ne!(
            external_str, internal_str,
            "External and internal descriptors should differ"
        );
    }

    #[test]
    fn same_mnemonic_same_descriptors() {
        let m1 = ZincMnemonic::parse(TEST_MNEMONIC).unwrap();
        let m2 = ZincMnemonic::parse(TEST_MNEMONIC).unwrap();

        let desc1 = taproot_descriptors(&m1, Network::Signet).unwrap();
        let desc2 = taproot_descriptors(&m2, Network::Signet).unwrap();

        assert_eq!(desc1.external.to_string(), desc2.external.to_string());
    }
}
