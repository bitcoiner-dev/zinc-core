## 2025-07-08 - Fast Bitwise Hex Encoding
**Learning:** In contexts where byte slices are frequently encoded to hex strings (e.g. `bytes_to_hex_lower`), using `String::push(char)` or `format!` within a loop incurs significant overhead due to repeated UTF-8 boundary validation or macro evaluation.
**Action:** Replace `String::push(char)` with direct zero-dependency bitwise nibble mapping. Push mapped bytes from a static `HEX_CHARS` lookup table directly into a pre-allocated `Vec<u8>`, and use `String::from_utf8(out).unwrap()` at the very end to bypass iterative string validation.
