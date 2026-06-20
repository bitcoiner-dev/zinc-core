## 2026-06-20 - Optimize bytes_to_lower_hex
**Learning:** In Rust, using the `write!` macro with `std::fmt::Write` inside a loop to format bytes to lower hex strings introduces generic formatting overhead. This overhead can be avoided by directly using a highly optimized library such as `hex` which maps nibbles more efficiently.
**Action:** When byte-to-hex conversion is needed, default to using the `hex` crate (e.g., `hex::encode`) instead of rolling custom loops with the `write!` macro.
