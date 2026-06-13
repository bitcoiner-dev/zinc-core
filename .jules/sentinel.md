## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2025-02-14 - Prevent Panics on BIP32 Derivation Bounds
**Vulnerability:** Unvalidated dynamic inputs passed to `ChildNumber::from_hardened_idx` and `from_normal_idx` with `.unwrap()` can cause WASM runtime panics and DoS attacks if values exceed 2^31.
**Learning:** `bdk_wallet` derivation functions panic when inputs exceed BIP32 bounds. Implicit assumptions about input safety can expose critical routines (like key derivation) to denial of service.
**Prevention:** Always handle derivation bounds safely by returning a `Result` using `.map_err()` instead of `.unwrap()` on user-controlled or variable derivation indices.
