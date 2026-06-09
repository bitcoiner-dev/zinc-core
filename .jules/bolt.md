## 2024-11-20 - Hex Encoding Formatting Overhead
**Learning:** Using `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string hex conversions introduces significant generic formatting overhead. This is a common performance pitfall in Rust when dealing with cryptography or raw byte processing.
**Action:** Always prefer specialized crates like `hex` (e.g., `hex::encode`) or direct nibble mapping over `write!` for high-performance byte-to-hex-string conversions.
