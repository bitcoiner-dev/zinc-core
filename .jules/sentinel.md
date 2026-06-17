## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-06-17 - Avoid WASM Runtime Panics During Script Parsing
**Vulnerability:** Calling `.unwrap()` on `try_into()` when parsing untrusted variable-length byte slices from Bitcoin PSBT scripts (e.g., `script_bytes[cursor + 1..cursor + 3]`) can cause WASM runtime panics (Denial of Service) if expected bytes are missing due to malformed input.
**Learning:** Panicking on unvalidated external inputs is a security risk, especially in web-facing WASM contexts where a crash aborts the user's workflow. Always assume external script bytes might be truncated or malformed, even if previous basic bounds checks (like `cursor + 3 <= script_bytes.len()`) exist, as complex parsing logic might drift.
**Prevention:** Always use safe fallbacks like `.unwrap_or([0, 0])` or gracefully return an error (e.g., `.map_err()`) when converting or extracting data from byte slices to prevent unexpected panics.

## 2024-06-17 - Prevent Derivation Panics from Malformed BIP32 Indices
**Vulnerability:** Unvalidated derivation indices passed to BDK's `ChildNumber::from_hardened_idx` or `ChildNumber::from_normal_idx` combined with `.unwrap()` can cause runtime panics (Denial of Service) if user-provided or corrupted persistent values exceed 2^31 (the BIP32 maximum).
**Learning:** Hardened and normal indices must strictly adhere to BIP32 bounds. Even if values typically originate from trusted local derivation chains, user manipulation, persistent state corruption, or external descriptor inputs could introduce out-of-bounds indices.
**Prevention:** Replace `.unwrap()` with explicit error handling (e.g., `.map_err(|e| format!("Invalid index: {}", e))?`) to gracefully reject out-of-bounds index derivations instead of crashing the application.
