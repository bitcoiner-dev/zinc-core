## 2024-07-03 - Optimizing String hex serialization with Bitwise Mapping
**Learning:** `String::push(char)` and `write!` macros introduce unnecessary overhead when serializing bytes to hex strings because of UTF-8 validation and formatting overhead.
**Action:** Replace them with direct zero-dependency bitwise/nibble mapping using a static `HEX_CHARS` lookup table and pushing to a `Vec<u8>` followed by `String::from_utf8(out).unwrap()`.
