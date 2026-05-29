## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-29 - Unsafe Unwraps in Untrusted Parsing and Key Derivation
**Vulnerability:** Found multiple instances where `.unwrap()` or unhandled conversions on slices from untrusted byte streams and invalid variables could lead to runtime panics (Denial of Service). Specifically, in `src/ordinals/shield.rs` during PSBT parsing `try_into().unwrap()` was used, and in `src/builder.rs` `ChildNumber::from_hardened_idx` was unhandled and could panic for indices > 2^31.
**Learning:** Hardcoded constraints on data types or specific byte layouts can lead to panic when handling network inputs like PSBTs. While it is rare, out-of-bounds `ChildNumber` creation during Key Derivation can panic.
**Prevention:** Always gracefully fallback or return an error (`map_err`) when parsing external inputs or deriving user variables without known lengths.
