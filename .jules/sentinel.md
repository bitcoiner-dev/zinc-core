## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-06-09 - [Panic Risk from unwrap on derivation indices]
**Vulnerability:** Found uses of `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx`. If an input index exceeds 2^31, it causes the WASM runtime to panic and crash (Denial of Service).
**Learning:** External inputs mapped to derivation indices must be properly bounds-checked or gracefully handled, as `ChildNumber` constructors panic on invalid values.
**Prevention:** Avoid using `.unwrap()` on `ChildNumber` creation. Use `.map_err()` to return a safe `Result::Err` to the caller.
