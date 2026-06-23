## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-06-23 - Unvalidated Dynamic User Inputs Passed to BIP32 Derivation Index
**Vulnerability:** Unvalidated dynamic user inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` or `from_normal_idx` combined with `.unwrap()` can cause WASM runtime panics (DoS) if expected bytes are missing or if the values exceed bounds (2^31).
**Learning:** Always use safe error propagation (e.g., `.map_err()`) for dynamic derivation indices instead of `.unwrap()`.
**Prevention:** Avoid blindly using `.unwrap()` on dynamic, external, or unpredictable inputs where panics are a real risk.
