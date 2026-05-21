## 2024-05-21 - HashMap Pre-allocation for Known Inscriptions
**Learning:** Pre-allocating `HashMap` capacities using `with_capacity(len)` inside performance-critical loops (like processing PSBTs with many inscriptions) prevents expensive dynamic memory reallocation, improving CPU efficiency and memory stability in WASM environments.
**Action:** Always pre-allocate collections like HashMaps when the maximum capacity or upper bound is known in advance from an existing collection's length.
