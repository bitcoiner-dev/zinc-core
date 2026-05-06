## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-06 - Replace unwrap on script parsing and integer casts
**Vulnerability:** Use of `.unwrap()` on fallible operations like `try_from` or `try_into` on externally derived inputs/script slices poses a risk of panics resulting in Denial of Service (DoS) attacks.
**Learning:** Always map errors to proper Result types (e.g. `OrdError::RequestFailed` or returning a `Result<..., String>`) instead of unwrapping, especially when dealing with parsed slice bounds or external integer types where bounds checks could fail.
**Prevention:** Avoid `.unwrap()` or `.expect()` on `try_from`/`try_into` conversions; map them to error results and propagate them to the caller to fail gracefully.
