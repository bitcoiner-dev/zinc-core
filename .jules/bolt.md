## 2024-06-13 - Fast Hex Serialization
**Learning:** Using the `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead. This codebase already has the `hex` crate available as a dependency which provides a highly optimized implementation.
**Action:** Replace manual byte-to-hex formatting loops with direct calls to `hex::encode(bytes)`. This provides measurable performance improvements during serialization (like `bytes_to_lower_hex`).
