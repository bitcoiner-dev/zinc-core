## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-07-09 - WASM Runtime DoS via unwrap on slice conversion
**Vulnerability:** Untrusted variable-length byte slices in PSBT parsing were being converted to arrays and explicitly unwrapped via `try_into().unwrap()`.
**Learning:** Missing bytes in dynamic input cause unwrap to panic, leading to a WASM runtime abort (DoS).
**Prevention:** Always use safe fallbacks like `.unwrap_or([0, 0])` or `.map_err()` when handling malformed/dynamic array conversions in Rust targeting WASM.
