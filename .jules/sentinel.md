## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2026-06-10 - Prevent DoS from unvalidated derivation indices
**Vulnerability:** Unsafe `.unwrap()` on `ChildNumber::from_hardened_idx` and `from_normal_idx` calls in `src/builder.rs` when parsing variable indices (like `index`, `account`, `purpose`) could cause WASM runtime panics and Denial of Service if the indices exceed the `2^31 - 1` limit for standard derivation paths.
**Learning:** Even internal operations like address derivation can be vulnerable if user-provided or dynamically tracked index variables grow out of bounds and trigger panics via `.unwrap()`. Safe error propagation prevents DoS.
**Prevention:** Always handle bip32 `ChildNumber` creation safely, using `.map_err()` instead of `.unwrap()` to fail gracefully, particularly in public APIs or frequently called internal functions.
