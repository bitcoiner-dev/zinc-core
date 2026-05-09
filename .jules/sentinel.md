## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-10 - [Unhandled Panics in BIP32 ChildNumber Derivation]
**Vulnerability:** Found unhandled `.unwrap()` calls when creating `ChildNumber` instances from potentially dynamic derivation path indices (e.g., purpose, coin_type, account, chain, index) in `src/builder.rs`. If these inputs exceed the valid range for normal or hardened indices (2^31 - 1), it would trigger a runtime panic, leading to a Denial of Service (DoS).
**Learning:** Even internal helper methods relying on standard derivation structures can panic if input indices aren't strictly validated or handled gracefully, especially if inputs are influenced dynamically.
**Prevention:** Always use safe fallbacks or `.map_err()` to propagate bounds-checking errors when initializing boundary-constrained types like `ChildNumber::from_hardened_idx` or `ChildNumber::from_normal_idx`.
