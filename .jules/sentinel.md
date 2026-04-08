## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-31 - [Panic Risk from unwrap on derivation bounds]
**Vulnerability:** Found uses of `.unwrap()` on `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx` and `from_normal_idx` in `derive_private_key_internal` and `sign_inscription_script_paths`. Passing unvalidated dynamic or user-controlled values (like `purpose`, `account`, `chain`, and `index`) to these derivation boundary parsers can cause the application and WASM runtime to panic if the value exceeds 2^31, leading to a Denial of Service (DoS).
**Learning:** Hardcoded constants passed to boundary parsers like index derivation functions are safe with `.unwrap()`, but dynamic external variables are not and require proper validation to prevent runtime panics.
**Prevention:** Always use safe `Result`-returning wrapper functions (e.g. `Self::child_hardened` or `Self::child_normal`) when creating derivation paths with dynamic inputs instead of chaining `.unwrap()`.
