## 2024-07-01 - Fast Hex Encoding
**Learning:** Using `String::push(char)` or the `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant overhead (e.g., UTF-8 validation or generic formatting).
**Action:** Replace it with direct zero-dependency bitwise/nibble mapping using a static `HEX_CHARS` lookup table and pushing to a `Vec<u8>` followed by `String::from_utf8(out).unwrap()`.
