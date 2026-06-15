## 2024-06-25 - Replace manual hex encoding loops
**Learning:** Manual byte-to-hex formatting loops using `write!` and `String::with_capacity()` have significant generic formatting overhead in Rust and are not optimal for performance-critical execution paths.
**Action:** Always prefer `hex::encode()` from the `hex` crate for byte-to-hex encoding tasks when executing within a hot loop or heavy data processing paths, as it maps directly to `String` using faster algorithms.
