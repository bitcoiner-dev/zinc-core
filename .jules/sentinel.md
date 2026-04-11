## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-04-11 - DoS Vulnerability via Unvalidated `ChildNumber` Indices
**Vulnerability:** Unsafe usage of `ChildNumber::from_hardened_idx(idx).unwrap()` and `ChildNumber::from_normal_idx(idx).unwrap()` across internal API functions (e.g. `derive_private_key_internal` and `sign_inscription_script_paths`).
**Learning:** These APIs could panic if passed dynamic or user-controlled values (indices >= 2^31), leading to a Denial of Service (DoS) attack through application crashing.
**Prevention:** Replaced direct `.unwrap()` invocations with safe wrapper methods (`Self::child_hardened` and `Self::child_normal`) that correctly return an error `Result`, propagating errors upwards and avoiding runtime panics.
