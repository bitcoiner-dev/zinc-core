## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx` and `from_normal_idx` when deriving BIP32 paths. Unvalidated derivation paths could cause panic and DoS if values exceed 2^31.
**Learning:** Type conversions for key derivation must be safely handled using `.map_err()`, as unvalidated inputs can lead to application crashes.
**Prevention:** Avoid using `.unwrap()` on derivation functions. Map errors properly (e.g. `map_err(|e| format!("Invalid index: {}", e))?`) to fail securely.
