## 2025-05-19 - Initial Setup
**Learning:** Found several places where `HashMap::new()` is used without pre-allocating capacity, specifically when iterating over `self.inscriptions` to build `known_inscriptions`.
**Action:** Use `HashMap::with_capacity(len)` where the number of items to insert is known in advance, preventing dynamic memory reallocations.
