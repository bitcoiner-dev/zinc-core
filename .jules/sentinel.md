## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-04-26 - [Unsafe Integer Cast to ChildNumber]
**Vulnerability:** The code was using `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(idx).unwrap()` and `from_normal_idx` which could panic (DoS) if unvalidated, dynamic, or potentially out-of-bounds user values exceeded the 2^31 bounds for child number indices.
**Learning:** Using `.unwrap()` on operations that parse or validate runtime/external numerical values can cause panics in Rust and WASM environments if those values do not conform to expected boundaries (e.g. > 2^31 - 1).
**Prevention:** Always create safe helper wrappers that return `Result` for integer casting functions, allowing safe error propagation with `?` instead of hard crashes.
