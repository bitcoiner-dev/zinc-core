## 2025-06-11 - Fast Hex Encoding
**Learning:** Using `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead.
**Action:** Replace it with an optimized crate like `hex` (e.g., `hex::encode`) for measurable performance improvements, especially in tight loops or critical paths like serialization.
