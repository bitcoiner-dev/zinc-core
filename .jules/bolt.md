## 2024-05-19 - Avoid Format string allocation for Hex encoding
**Learning:** Using `format!("{b:02x}")` within a `map().collect()` loop introduces a significant allocation overhead per byte. A static lookup array (e.g. `HEX_CHARS[(byte >> 4) as usize]`) and pushing directly into a pre-allocated `Vec<u8>` is substantially faster for basic hex encoding.
**Action:** Always prefer a bitwise static lookup implementation instead of relying on standard library `format!` macros for tight loops like hex conversion.
