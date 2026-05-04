## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-04 - Unvalidated Derivation Bounds Causing Panics
**Vulnerability:** Calling `.unwrap()` on `ChildNumber::from_hardened_idx` or `ChildNumber::from_normal_idx` with dynamically provided bounds (e.g., `purpose`, `account`, `index`) can cause panics and potential DoS attacks if values exceed 2^31.
**Learning:** External inputs like derivation indices must always be strictly validated and handled safely rather than unconditionally unwrapping values. Statically known valid constants (e.g. coin type, chain 0) are safe to unwrap, but not dynamic inputs.
**Prevention:** Map index creation errors properly to return `Result::Err` values (e.g., using `.map_err()`) preventing potential DoS vulnerabilities by handling out-of-bounds errors gracefully.
