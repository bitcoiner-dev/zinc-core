## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2026-06-26 - Prevent DoS from untrusted derivation indices
**Vulnerability:** BIP32 derivation using `.unwrap()` on `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` with dynamic variables (`purpose`, `coin_type`, `account`, `chain`, `index`).
**Learning:** `unwrap()` on dynamic variable derivation paths can lead to WASM runtime panics (DoS) if indices exceed derivation bounds (2^31).
**Prevention:** Always use safe error propagation (e.g., `.map_err()`) for dynamic derivation indices instead of `.unwrap()`.
