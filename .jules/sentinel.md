## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-30 - [Panic Risk from unwrap on ChildNumber derivation]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` when deriving keys in `builder.rs`. If the index passed is out of range (>= 2^31), this conversion fails and unwrapping causes the application (including the WASM runtime) to panic and crash, leading to a Denial of Service (DoS) vulnerability.
**Learning:** Index inputs from user state or external inputs used to derive BIP32 child keys can cause application panics if bounds are exceeded and `.unwrap()` is used.
**Prevention:** Always use safe error handling and bubble up the error (e.g. using `.map_err(...)?`) when creating `ChildNumber` from an index, avoiding `.unwrap()`.
