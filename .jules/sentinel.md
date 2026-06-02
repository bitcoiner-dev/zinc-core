## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-06-02 - Prevent Denial of Service Panics on Malformed Inputs and Derivations
**Vulnerability:** Unsafe slice-to-array conversions (`try_into().unwrap()`) on variable-length script chunks when parsing Ordinal envelopes, and unchecked BIP32 derivation index boundaries (`from_hardened_idx(idx).unwrap()`), could trigger application-crashing panics if encountering malformed PSBTs or invalid user-supplied keys.
**Learning:** `bdk_wallet`'s ChildNumber derivation functions enforce hard limits (e.g. max `2^31-1`). Unwrapping this on dynamic inputs allows a local or remote DoS vector via panicking the WASM runtime or native app.
**Prevention:** Always handle Fallible API calls correctly. Use `.map_err()` to bubble up helpful error messages for derivations instead of panicking, and use `.unwrap_or([0, 0])` or proper bounds checking for variable slice casting.
