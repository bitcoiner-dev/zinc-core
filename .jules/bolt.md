## 2024-05-24 - Rust String Formatting Overhead
**Learning:** Using the `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead in Rust compared to using dedicated encoding functions.
**Action:** Replace manual loop-based byte-to-hex formatting with `hex::encode()` from the `hex` crate for better performance and cleaner code.
