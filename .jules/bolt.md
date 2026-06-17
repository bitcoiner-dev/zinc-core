## 2026-06-17 - Replaced generic string format write! with optimized hex crate
**Learning:** Using the `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead. This project already depends on the `hex` crate.
**Action:** Replaced loop-based `write!` implementation in `bytes_to_lower_hex` with `hex::encode(bytes)`. This provides a measurable performance improvement by avoiding formatting abstractions.
