## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-30 - [Panic Risk in BIP32 ChildNumber derivation]
**Vulnerability:** Found uses of `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx`. If these are called with dynamic/unvalidated indices exceeding bounds (e.g., values > 2^31-1 for normal indices), it can cause the application (especially in WASM environments) to panic, leading to DoS.
**Learning:** Hardcoded `.unwrap()` on derivation indices introduces critical vulnerability paths when components are exposed externally. Dynamic indices must be checked.
**Prevention:** Avoid unwrap() on index derivation tools. Always use `.map_err()` to surface the invalid derivation paths safely without panicking.
