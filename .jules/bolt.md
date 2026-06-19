## $(date +%Y-%m-%d) - Replaced write! with hex encoding
**Learning:** In contexts like converting byte arrays to hex strings, using `write!` with `std::fmt::Write` inside a loop introduces a significant generic formatting overhead. This codebase has a `bytes_to_lower_hex` method in `src/builder.rs` that suffers from this.
**Action:** Replace manual `write!` byte formatting loop with `hex::encode(bytes)`. This provides a measurable performance improvement and avoids unnecessary allocations and loop overhead.
