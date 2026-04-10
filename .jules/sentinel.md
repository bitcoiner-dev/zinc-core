## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2025-02-28 - DoS via Panic in BIP32 ChildNumber Derivation
**Vulnerability:** Calling `bdk_wallet::bitcoin::bip32::ChildNumber::from_hardened_idx(idx).unwrap()` (or `from_normal_idx`) panics when `idx` exceeds the maximum allowed value (`2^31 - 1`). When processing dynamically supplied or user-controlled index parameters (like `purpose`, `account`, `chain`, and `index`), this causes uncatchable DoS panics.
**Learning:** Hard-wrapping `.unwrap()` assumes indices are always within valid bounds, which cannot be guaranteed unless statically hardcoded. This exposes the application to denial-of-service vulnerabilities.
**Prevention:** Always use safe fallbacks or proper `Result`-returning wrappers (like `Self::child_hardened` or `Self::child_normal`) combined with `?` to gracefully propagate derivation boundary errors when the input values are dynamically constructed or provided by external inputs.
