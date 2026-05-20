## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-01 - [BIP32 Derivation DoS Panic]
**Vulnerability:** Unvalidated dynamic inputs passed to `ChildNumber::from_hardened_idx` and `from_normal_idx` using `.unwrap()` could trigger panics and DoS attacks if values exceed the maximum bound of 2^31 - 1.
**Learning:** Hardcoded bounds checks or unsafe unwraps should be avoided on user-controlled inputs during key derivation routines.
**Prevention:** Always handle potentially out-of-bounds derivation indices with `.map_err()` to return graceful errors instead of panicking.
