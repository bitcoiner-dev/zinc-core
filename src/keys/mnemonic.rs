//! BIP-39 Mnemonic wrapper with security features

use bip39::Mnemonic;
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::ZincError;

/// A wrapper around BIP-39 mnemonic with zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZincMnemonic {
    #[zeroize(skip)]
    inner: Mnemonic,
}

impl ZincMnemonic {
    /// Generate a new random mnemonic.
    ///
    /// # Arguments
    /// * `word_count` - Number of words (12 or 24)
    pub fn generate(word_count: u8) -> Result<Self, ZincError> {
        let entropy_len = match word_count {
            12 => 16, // 128 bits
            24 => 32, // 256 bits
            _ => return Err(ZincError::InvalidWordCount(word_count)),
        };

        let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
        rand::RngCore::fill_bytes(&mut OsRng, &mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| ZincError::MnemonicError(e.to_string()))?;

        Ok(Self { inner: mnemonic })
    }

    /// Parse a mnemonic from a phrase.
    pub fn parse(phrase: &str) -> Result<Self, ZincError> {
        let mnemonic = Mnemonic::parse_in(bip39::Language::English, phrase)
            .map_err(|e| ZincError::MnemonicError(e.to_string()))?;

        Ok(Self { inner: mnemonic })
    }

    /// Get the mnemonic words as a vector.
    pub fn words(&self) -> Vec<String> {
        self.inner.words().map(|w: &str| w.to_string()).collect()
    }

    /// Get the mnemonic phrase as a string.
    pub fn phrase(&self) -> String {
        self.inner.to_string()
    }

    /// Derive the seed from the mnemonic.
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.inner.to_seed(passphrase))
    }

    /// Get the inner mnemonic (for BDK integration).
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &Mnemonic {
        &self.inner
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_word_mnemonic() {
        let m = ZincMnemonic::generate(12).unwrap();
        assert_eq!(m.words().len(), 12);
    }

    #[test]
    fn generate_24_word_mnemonic() {
        let m = ZincMnemonic::generate(24).unwrap();
        assert_eq!(m.words().len(), 24);
    }

    #[test]
    fn invalid_word_count_fails() {
        let result = ZincMnemonic::generate(15);
        assert!(result.is_err());
    }

    #[test]
    fn parse_valid_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = ZincMnemonic::parse(phrase).unwrap();
        assert_eq!(m.words().len(), 12);
        assert_eq!(m.phrase(), phrase);
    }

    #[test]
    fn parse_invalid_mnemonic_fails() {
        let result = ZincMnemonic::parse("invalid mnemonic phrase");
        assert!(result.is_err());
    }

    #[test]
    fn seed_derivation_works() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = ZincMnemonic::parse(phrase).unwrap();
        let seed = m.to_seed("");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn passphrase_changes_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = ZincMnemonic::parse(phrase).unwrap();
        let seed1 = m.to_seed("");
        let seed2 = m.to_seed("password");
        assert_ne!(&seed1[..], &seed2[..]);
    }

    #[test]
    fn seed_matches_bip39_known_answer_vector() {
        // Canonical BIP-39 test vector: the "abandon ... about" mnemonic with an
        // empty passphrase derives a fixed 512-bit seed. Locks BIP-39 derivation.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = ZincMnemonic::parse(phrase).unwrap();
        let seed = m.to_seed("");
        // PERFORMANCE OPTIMIZATION (Bolt): Replaced slow format! macro in loop with direct bitwise lookup table mapping
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut out = Vec::with_capacity(seed.len() * 2);
        for byte in &*seed {
            out.push(HEX_CHARS[(byte >> 4) as usize]);
            out.push(HEX_CHARS[(byte & 0x0F) as usize]);
        }
        let hex = String::from_utf8(out).unwrap();
        assert_eq!(
            hex,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn parse_rejects_wrong_word_count() {
        // 11 words: a valid-looking phrase with a bad length must fail the checksum.
        let eleven =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(ZincMnemonic::parse(eleven).is_err());
    }
}
