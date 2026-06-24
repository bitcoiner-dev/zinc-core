## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2025-02-20 - [Panic Risk from unwrap on type conversions in builder.rs]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx(purpose)` and `ChildNumber::from_normal_idx(index)` when converting dynamic integer inputs to BIP32 child derivation paths. Unvalidated user input or bounds errors could trigger an unwrap panic, leading to a WASM application crash and Denial of Service.
**Learning:** Hardened and normal derivation indices must be handled safely, as unvalidated inputs passing maximum bounds (2^31) can crash execution instead of bubbling up errors gracefully.
**Prevention:** Avoid `.unwrap()` on `from_hardened_idx()` or `from_normal_idx()` for dynamic inputs, and map errors safely using `.map_err()`.
