
## 2024-04-14 - Pre-allocate known_inscriptions map capacity
**Learning:** In loops or processes that rebuild state maps like `known_inscriptions` based on an existing collection (e.g., `self.inscriptions`), failing to pre-allocate capacity results in expensive dynamic memory reallocations. This can act as a performance bottleneck when iterating over large datasets.
**Action:** Use `HashMap::with_capacity(len)` instead of `HashMap::new()` when the number of items to be inserted is known or can be upper-bounded, to prevent dynamic memory reallocations.
