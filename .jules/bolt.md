## $(date +%Y-%m-%d) - Replaced formatting macro loop with `hex::encode`
**Learning:** Using `write!` macro with `std::fmt::Write` in a loop for simple byte-to-string conversions (like hex encoding) introduces significant generic formatting overhead.
**Action:** Use an optimized crate like `hex` (or direct bitwise mapping) for measurable performance improvements when encoding bytes to strings.
