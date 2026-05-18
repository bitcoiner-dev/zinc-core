## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-31 - [Panic Risk from unwrap on derivation path index generation]
**Vulnerability:** Found uses of `.unwrap()` when converting dynamically provided integers (e.g. `purpose`, `coin_type`, `account`, `chain`, `index`) to `ChildNumber` using `from_hardened_idx` and `from_normal_idx`. If these external inputs or network-derived constants exceed BIP32 bounds (2^31), it will panic, causing a Denial of Service (DoS).
**Learning:** Even integers that seem implicitly bounded by design can crash the process (or WASM runtime) if passed to a fallible method like `from_hardened_idx` and unwrapped, particularly when sourced from generic parameters or untrusted sources.
**Prevention:** Handle fallible derivations safely by mapping the error to a String or Result instead of `.unwrap()`.
