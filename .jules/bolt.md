## 2024-07-05 - Direct Bitwise Hex Encoding Over `format!` Loop

**Learning:** Using `format!("{b:02x}")` within an `iter().map().collect()` loop introduces significant runtime overhead. It requires generic string formatting, memory allocation per loop iteration, and UTF-8 validation when joining the chunks back together.

**Action:** Replace looped string formatting for byte-to-hex conversion with direct bitwise/nibble mapping. Use a statically pre-allocated `Vec<u8>` capacity and a lookup table (e.g. `b"0123456789abcdef"`) to derive nibbles `(b >> 4)` and `(b & 0xf)`. Finally, convert the raw buffer to a string using `String::from_utf8(out).unwrap()`, bypassing the overhead of standard library formatting machinery.
