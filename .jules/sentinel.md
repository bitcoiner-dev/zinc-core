## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-05-30 - Fix Unhandled BIP32 Derivation Panics
**Vulnerability:** User-controlled dynamic derivation indices (`purpose`, `account`, `index`) were passed to `ChildNumber::from_hardened_idx` and `from_normal_idx` with `.unwrap()`, causing DoS panics if bounds (2^31) are exceeded.
**Learning:** Blindly unwraping derivations based on user inputs or generic function arguments can crash the entire application or WASM runtime when bad inputs are provided.
**Prevention:** Always propagate errors cleanly with `.map_err()` for dynamic inputs, while keeping `.unwrap()` strictly for statically known safe values to avoid security theater.
