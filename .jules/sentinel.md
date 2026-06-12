## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-06-12 - Secure Derivation Path Handling

**Vulnerability:** Unvalidated dynamic or user-controlled inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` or `from_normal_idx` with `.unwrap()` can cause panics and DoS attacks if values exceed 2^31.
**Learning:** Found in `src/builder.rs` where derivation indices are used to build derivation paths. Using `.unwrap()` for these values can crash the application (DoS) if invalid numbers are passed.
**Prevention:** Always handle derivation bounds safely by returning a `Result` (e.g., using `.map_err(|e| format!("...", e))?`). Also avoid 'security theater' by ignoring static bounds, but here indices are dynamically requested and used.
