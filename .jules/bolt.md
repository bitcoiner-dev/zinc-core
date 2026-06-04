## 2026-06-04 - Optimizing Hex Encoding
**Learning:** Using `format!("{b:02x}")` in a loop over bytes to perform hex encoding in Rust is extremely slow due to the overhead of Rust's generic formatting machinery.
**Action:** Replace `iter().map(|b| format!("{b:02x}")).collect()` with `hex::encode(digest)` using the highly optimized `hex` crate for measurable performance improvements, especially for operations like hashing and converting digests to hex strings.
