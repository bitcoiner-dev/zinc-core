## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-17 - [BIP-32 Derivation Panic DoS]
**Vulnerability:** User-controlled input passed to `ChildNumber::from_hardened_idx` and `from_normal_idx` using `.unwrap()` in `src/builder.rs`. This can cause panics and DoS attacks if values exceed $2^{31}$.
**Learning:** External or generalized index parameters for key derivation paths must be treated as untrusted and fallible.
**Prevention:** Always handle BIP-32 derivation bounds safely by returning a `Result` (e.g., using `.map_err(|e| e.to_string())?`) instead of `.unwrap()`.
