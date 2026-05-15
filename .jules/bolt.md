## 2024-05-18 - HashMap Pre-allocation for `known_inscriptions`

**Learning:** During loop intensive operations (like iterating over all known inscriptions to build an optimization map like `known_inscriptions`), pre-allocating the `HashMap` with `HashMap::with_capacity(len)` drastically improves performance by avoiding multiple internal reallocations and memory fragmentation as the map grows.

**Action:** Whenever converting a `Vec` or iterating over an array whose final size is roughly bounded or exactly known into a `HashMap`, always prefer `HashMap::with_capacity(len)` instead of `HashMap::new()`.
