## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2025-05-07 - [Prevent DoS via unhandled ChildNumber bounds]
**Vulnerability:** In `src/builder.rs`, `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(account).unwrap()` and `ChildNumber::from_normal_idx(index).unwrap()` panic if the user-controlled or dynamically calculated value reaches 2^31 (`0x80000000`). This can cause Denial of Service (DoS) panics.
**Learning:** `from_hardened_idx` and `from_normal_idx` return `Result`s because they have internal upper bounds (must be less than `2^31`). Blindly `.unwrap()`-ing these conversions inside key derivation functions poses a security risk when processing external inputs or loop boundaries.
**Prevention:** Always propagate `ChildNumber` derivation errors via `.map_err()` instead of `.unwrap()`.
