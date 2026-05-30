## 2025-02-12 - Replacing macro `write!` with simple mapping in hex encoding
**Learning:** `std::fmt::Write` via the `write!` macro is significantly slower for simple tasks like hex encoding bytes compared to a direct mathematical mapping (e.g., bitwise shift and mask for nibbles) or using `hex::encode`.
**Action:** Replace uses of `write!` in `bytes_to_lower_hex` or similar hand-rolled hex encoders with an optimized mapping to chars directly for measurable performance improvement.
