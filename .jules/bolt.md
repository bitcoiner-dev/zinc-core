## 2025-04-17 - Pre-allocate known_inscriptions HashMaps
**Learning:** `HashMap::new()` causes expensive dynamic reallocations during inserts in a loop.
**Action:** Always use `HashMap::with_capacity()` when the upper bound of elements is known.
