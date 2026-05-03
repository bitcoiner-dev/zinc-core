## 2024-05-03 - [Optimize Inscription HashMap Initialization]
**Learning:** Initializing HashMap using `HashMap::new()` in performance critical operations (like parsing PSBTs with potentially many inscriptions) will result in many dynamic reallocations which hurts performance. Using `with_capacity` prevents this.
**Action:** When creating a map from an existing collection like `self.inscriptions`, initialize the HashMap using `HashMap::with_capacity(len)` to pre-allocate memory and improve runtime performance.
