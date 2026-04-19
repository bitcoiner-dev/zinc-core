## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-30 - [Panic Risk from unchecked child derivation paths]
**Vulnerability:** Found `unwrap()` calls on `ChildNumber::from_hardened_idx` and `from_normal_idx` when deriving child paths in wallet derivation loops inside `src/builder.rs`. This can cause a panic and DoS (especially in WASM where panics crash the instance) if indices (e.g. `index` or `account`) exceed $2^{31}$.
**Learning:** `ChildNumber::from_hardened_idx` and `from_normal_idx` validate bounds (less than $2^{31}$). Passing external or dynamically growing indices without catching errors invites severe failures.
**Prevention:** Always handle the `Result` from `ChildNumber` creation safely instead of calling `unwrap()`, so the caller receives a graceful error string instead of terminating the execution thread.
