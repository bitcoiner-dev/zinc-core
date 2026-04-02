## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-31 - [Panic Risk from unwrap on BIP32 derivation]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx` and `from_normal_idx` in `src/builder.rs`. This can cause the application (and particularly the WASM runtime) to panic and crash if the index is invalid, leading to a Denial of Service (DoS).
**Learning:** When deriving BIP32 child keys, even with hardcoded indices, handling the `Result` gracefully is a defense-in-depth measure to prevent panics if values become dynamic or invalid.
**Prevention:** Always use safe fallbacks or map errors (e.g., using `.map_err(...)?` or the internal helper functions `child_hardened` and `child_normal`) instead of `.unwrap()` when deriving child keys.
