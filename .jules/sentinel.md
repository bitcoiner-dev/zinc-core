## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2025-02-05 - DoS via Unhandled Derivation Path Panics
**Vulnerability:** Unvalidated dynamic user inputs (like `purpose`, `account`, `chain`, and `index`) passed to `ChildNumber::from_hardened_idx` or `ChildNumber::from_normal_idx` with `.unwrap()` caused panics and potential Denial of Service (DoS) attacks if values exceeded 2^31.
**Learning:** `ChildNumber::from_hardened_idx` and `from_normal_idx` enforce that the index must not exceed 2^31 (the non-hardened bounds). The code used `.unwrap()`, implicitly trusting bounds, which panics when limits are exceeded.
**Prevention:** Always handle variable/user-controlled derivation bounds safely by propagating a `Result` via `map_err(...)` instead of `unwrap()`.
