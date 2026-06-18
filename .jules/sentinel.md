## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.
## 2024-06-18 - [Panic Risk from unvalidated BIP32 derivation indices]
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx(purpose)` and `from_normal_idx(index)` when passing user-controlled dynamic `u32` inputs. If the inputs exceed `2^31 - 1`, the functions return an error, and the `.unwrap()` will panic, crashing the WASM runtime (DoS).
**Learning:** Unvalidated dynamic inputs passed directly to BIP32 index conversion functions are a critical DoS vector because out-of-bounds values trigger panics via `.unwrap()`.
**Prevention:** Always use safe error handling (e.g., `.map_err(...)`) when dealing with user-provided or external derivation indices to fail securely.
