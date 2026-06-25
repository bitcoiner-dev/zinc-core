## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-06-25 - Safe Derivation Indices
**Vulnerability:** Unvalidated dynamic user inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` or `from_normal_idx` combined with `.unwrap()` can cause WASM panics (DoS) if the values exceed bounds (2^31).
**Learning:** This codebase compiles to WASM, where Rust panics lead to immediate application crash and DoS without standard panic recovery. Therefore, unvalidated dynamic indices cannot safely assume they fall under 2^31 boundary limits.
**Prevention:** Always use safe error propagation (e.g., `.map_err(|e| e.to_string())?`) for dynamic derivation indices to avoid panic-based DoS in a WASM environment.
