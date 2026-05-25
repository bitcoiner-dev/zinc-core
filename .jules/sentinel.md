## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-25 - Unsafe ChildNumber Derivation in BDK Wallet
**Vulnerability:** Unsafe use of `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` when deriving keys. If an index exceeds 2^31 (e.g. from malicious or malformed input), `from_hardened_idx`/`from_normal_idx` panics, potentially causing a Denial-of-Service (DoS).
**Learning:** Hardcoded indices or dynamic user-controlled derivation paths should always be bounds-checked and handle invalid values gracefully via `Result` mapping, instead of panicking.
**Prevention:** Use `.map_err()` to propagate index derivation errors and return a `Result` type string instead of using `.unwrap()` on `ChildNumber` creation.
