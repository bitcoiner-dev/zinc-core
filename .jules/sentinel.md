## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-16 - Safe bounds check for derivation index conversions
**Vulnerability:** Unsafe derivation index `.unwrap()` causing potential application panic DoS when derivation arguments `from_hardened_idx` and `from_normal_idx` passed unbounded/invalid inputs (above `2^31`).
**Learning:** External user parameters (network derivation purpose/account/index) mapped directly into BIP-32 integer structs can violate hard bounds in BDK wallet resulting in unwrapping errors, leading to unexpected hard crashes.
**Prevention:** Bound inputs via `.map_err()` instead of blindly unwrapping `.unwrap()`, providing gracefully bubbled result errors back to callers or calling environments like WASM.
