## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2025-02-28 - [Panic Risk from unwrap on bip32 ChildNumber derivation]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx(idx)` and `ChildNumber::from_normal_idx(idx)` when passing large indices. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX / 2` (or simply `2^31`), leading to a Denial of Service (DoS) vulnerability.
**Learning:** Hardened index derivations and `u8::try_from` casting are prone to panics if input ranges are exceeded. `unwrap` must be carefully avoided on user inputs.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on key derivation and number truncation. Map the errors with safe messages to allow graceful failures and return Result instead to fail securely.
