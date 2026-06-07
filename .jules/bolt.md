## 2024-06-07 - Avoid write! Macro in byte-to-hex Encoding Loops
**Learning:** Using the `write!` macro with `std::fmt::Write` inside a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead. It is a slow pattern for tight loops.
**Action:** Replace manual iteration and `write!` macro loops with the optimized `hex::encode` from the `hex` crate for measurable performance improvements when encoding bytes to hex strings.
