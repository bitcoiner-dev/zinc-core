## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-13 - Unvalidated BIP32 Derivation Indices
**Vulnerability:** Unvalidated dynamic inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` using `.unwrap()` could cause a panic if the requested index exceeds 2^31, leading to a potential DoS attack vector.
**Learning:** Hardcoded indices or evaluated boolean constants like `coin_type` are safe to unwrap, but parameters originating from external inputs or loops such as `index`, `account`, and `purpose` must be propagated safely.
**Prevention:** Always use `.map_err(...)` or proper error handling for functions that perform bounds checks on dynamic inputs, specifically avoiding `.unwrap()` on type or bounds conversions like `from_hardened_idx`.
