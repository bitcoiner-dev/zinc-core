## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2025-02-24 - [Panic Risk from unwrap on ChildNumber conversion]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` when deriving wallet paths. This can cause the application to panic and crash if the derivation index exceeds the maximum valid value (2^31 - 1), leading to a Denial of Service (DoS) attack if the indices are user-controlled or dynamically supplied via an external system.
**Learning:** Unvalidated dynamic inputs passed to BDK/Bitcoin derivation index parsers with `.unwrap()` are a DoS vector.
**Prevention:** Avoid using `.unwrap()` on `ChildNumber::from_*_idx`. Handle derivation bounds safely by returning a `Result` mapping the error, such as `.map_err(|e| format!("Invalid index: {}", e))?`.
