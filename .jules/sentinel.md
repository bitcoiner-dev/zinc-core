## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-04-25 - Fix Panic Vulnerability in BIP32 ChildNumber Creation
**Vulnerability:** External or unvalidated derivation indices passed to `ChildNumber::from_hardened_idx(idx).unwrap()` and `ChildNumber::from_normal_idx(idx).unwrap()` exposed the application to potential panics if inputs exceeded bounds (e.g., index > 2^31 - 1). This could be exploited for DoS attacks or cause unpredictable crashes in both Rust and WASM contexts.
**Learning:** Hardcoded `.unwrap()` calls on functions that parse numeric user-controlled or dynamically generated IDs are dangerous, even if inputs are *expected* to be within valid ranges. In security contexts, all derivation path construction must cleanly handle invalid indices using standard error propagation.
**Prevention:** Replace `.unwrap()` with `Result`-returning helper functions (e.g., `child_hardened` and `child_normal`) that map errors securely without halting the runtime.
