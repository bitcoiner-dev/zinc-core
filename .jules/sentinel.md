## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-06-30 - Prevent WASM Panics from Unsafe byte conversion
**Vulnerability:** Unsafe `.unwrap()` calls on `try_into()` when parsing variable-length byte slices in `src/ordinals/shield.rs` can cause WASM runtime panics (DoS) if malformed data is encountered.
**Learning:** Rust's strict safety checks will panic if `try_into()` fails to convert a slice to a fixed-size array. In WASM contexts, these panics abruptly terminate execution, leading to Denial of Service vulnerabilities when processing untrusted input.
**Prevention:** Always use safe fallbacks like `.unwrap_or()` or propagate errors using `.map_err()` when converting dynamic/untrusted byte slices to fixed-size arrays.
