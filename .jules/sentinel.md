## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-18 - Fix unvalidated bip32 derivation index panics
**Vulnerability:** Unvalidated dynamic inputs passed to `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` or `from_normal_idx` with `.unwrap()` can cause panics and DoS attacks if values exceed 2^31.
**Learning:** Found unvalidated user inputs (like `purpose`, `account`, `chain`, `index`) directly driving BIP32 path derivation components which panics when invalid bounds are provided, crashing the application.
**Prevention:** Always validate derivation bounds safely by handling results or using `.map_err` instead of `.unwrap()`.
