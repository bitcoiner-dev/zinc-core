## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-06-03 - Unsafe BIP32 Child Number Derivation Unwraps
**Vulnerability:** In `src/builder.rs`, `ChildNumber::from_hardened_idx(idx)` and `ChildNumber::from_normal_idx(idx)` were used with `.unwrap()` when deriving key paths. If the user-supplied index or parameters exceed the BIP32 bounds (2^31), this triggers a panic, potentially leading to a Denial of Service.
**Learning:** Even internal API wrappers can receive indices dynamically derived or directly supplied by external callers. Applying `.unwrap()` on fallible value constraints in paths used for authentication or cryptography poses a crash risk.
**Prevention:** Always propagate BIP32 index conversion errors cleanly via `Result` using `.map_err()` instead of panicking, adhering to defense in depth and safe failure.
