## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2025-02-23 - Prevent Panics on Invalid Derivation Indices
**Vulnerability:** Unvalidated derivation indices passed dynamically to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` with `.unwrap()` caused panics and potential Denial of Service (DoS) attacks if values exceeded 2^31.
**Learning:** Statically typed arguments do not guarantee bounded values at runtime. Untrusted dynamically provided index values must always be parsed defensively.
**Prevention:** Always handle bounds for dynamic derivation paths gracefully by returning a `Result` via `.map_err()`, instead of relying on `.unwrap()`.
