## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-24 - Unsafe BIP32 ChildNumber Derivation Indices
**Vulnerability:** Unvalidated dynamic or user-controlled inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` or `from_normal_idx` with `.unwrap()` can cause panics and DoS attacks if values exceed 2^31.
**Learning:** Hardcoded indices are fine to unwrap, but dynamic variables (like `account`, `index`, `purpose`, etc.) need safe error handling using `Result`.
**Prevention:** Always use safe fallbacks like `.map_err()` to handle `from_hardened_idx` and `from_normal_idx` derivation bounds safely instead of `.unwrap()` on dynamic values.
