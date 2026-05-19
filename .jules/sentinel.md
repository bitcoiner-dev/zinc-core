## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-19 - DoS via Unvalidated Derivation Indices
**Vulnerability:** Panics were possible when deriving keys using `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` with unvalidated integer indices, causing Denial of Service via `unwrap()`.
**Learning:** Always map errors when instantiating bounds-checked values from parameters or dynamic inputs rather than using `unwrap()`, while it is okay to keep unwraps for statically known valid constants.
**Prevention:** Ensure all `from_hardened_idx` and `from_normal_idx` calls map the potential error back to the caller gracefully.
