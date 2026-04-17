sed -i 's/bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(\(.*\)).unwrap()/Self::child_hardened(\1)?/g' src/builder.rs
sed -i 's/bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(\(.*\)).unwrap()/Self::child_normal(\1)?/g' src/builder.rs
