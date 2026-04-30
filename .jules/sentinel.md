## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-18 - Fix DoS vulnerability in key derivation bounds checks
**Vulnerability:** The application used `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` calls when deriving keys. Large inputs (>= 2^31) would trigger an `InvalidChildNumber` panic, potentially leading to a Denial of Service (DoS).
**Learning:** Always validate boundaries and handle errors safely instead of panicking when using generic bounds parsing for external or unpredictably sourced index parameters like purpose, coin type, account, chain, and index.
**Prevention:** Use `.map_err()` to surface descriptive errors instead of hard-crashing via `.unwrap()` when casting or configuring `ChildNumber` derivation indices.
