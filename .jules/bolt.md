## 2024-05-16 - Pre-allocate HashMap Capacity in Wallet Builder

**Learning:** When generating maps dynamically like `known_inscriptions`, initializing them using `HashMap::new()` causes repeated dynamic memory reallocations during large loops, degrading performance.
**Action:** Replace `HashMap::new()` with `HashMap::with_capacity(len)` bounded to the exact data source populating the map (`self.inscriptions.len()`) to avoid dynamic reallocations in large `known_inscriptions` map building processes.
