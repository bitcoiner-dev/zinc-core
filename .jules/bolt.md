
## 2024-05-18 - HashMap Pre-allocation for Derived Collections
**Learning:** When building large `HashMap` instances by iterating over existing collections (like `self.inscriptions` or transaction lists) without pre-allocating capacity, Rust's `HashMap` dynamically reallocates memory multiple times. This is a common performance pitfall that wastes CPU cycles.
**Action:** Always check `HashMap::new()` initializations in tight loops or when processing potentially large datasets. Replace them with `HashMap::with_capacity(len)` when the final size (or an upper bound) is known from the source collection.
