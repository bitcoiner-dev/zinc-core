## 2024-05-30 - [Panic Risk from unwrap on type conversions]
**Vulnerability:** Found uses of `.unwrap()` on `u32::try_from(vout)` when converting from `usize` in PSBT and transaction output parsing. This can cause the application (and particularly the WASM runtime) to panic and crash if the index exceeds `u32::MAX`, leading to a Denial of Service (DoS).
**Learning:** Type conversions, especially from `usize` to narrower types like `u32` when handling potentially large or external inputs (like PSBT inputs/outputs), are prone to panic if unhandled.
**Prevention:** Avoid using `.unwrap()` or `.expect()` on `TryFrom` conversions in parsing and handling user-provided data. Use safe fallbacks or map errors (e.g. `OrdError::RequestFailed` or returning an error `Result`) instead to fail securely.

## 2024-05-31 - [Integer Truncation Vulnerability on External Data Parsing]
**Vulnerability:** Found an unsafe `vout as u32` integer cast when processing transaction outputs in PSBT analysis (`src/ordinals/shield.rs`). This could lead to silent integer truncation (where the upper bits are discarded without an error) if the number of outputs exceeds `u32::MAX`, resulting in undefined behavior or security bypasses on extremely large inputs.
**Learning:** Silent integer truncation is dangerous because it fails to explicitly report an error and continues with invalid data. This is particularly risky when analyzing external data formats like PSBTs.
**Prevention:** Avoid the `as` keyword for narrowing conversions. Always use `TryFrom` (e.g., `u32::try_from(vout)`) and handle the `Result` gracefully (e.g., mapping to a structured error like `OrdError::RequestFailed`) to ensure bounds checks are strictly enforced.
