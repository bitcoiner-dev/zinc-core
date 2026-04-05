## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-06-01 - [Panic Risk from unwrap on BIP32 Child Derivations]
**Vulnerability:** Found uses of `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` when deriving keys using potentially dynamic/user-controlled indices (such as account indices) in `src/builder.rs`. If values exceed the allowed bounds (e.g., $2^{31}$ for hardened indices), it causes panics and DoS, especially in WASM environments.
**Learning:** Unvalidated inputs passed to derivation functions can crash the application.
**Prevention:** Avoid using `.unwrap()` on `from_hardened_idx` and `from_normal_idx`. Always use `Result`-returning wrappers (like `map_err`) to handle derivation bounds safely and fail gracefully.
