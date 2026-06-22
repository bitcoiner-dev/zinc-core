## 2025-02-12 - Replaced generic write! macro with direct hex crate usage
**Learning:** Using the `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead.
**Action:** Replace it with an optimized external crate like `hex` (e.g. `hex::encode(bytes)`) for measurable performance improvements when simple byte-to-hex encoding is needed.
