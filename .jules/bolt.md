## 2024-06-25 - [Fast-path checks using HashSets]
**Learning:** O(n) linear searches over vectors (like `self.inscriptions`) inside hot loops (like transaction output iteration) can cause significant performance degradation. However, using pre-existing `HashSet` caches (like `self.inscribed_utxos`) allows us to implement O(1) fast-path checks, avoiding the expensive linear lookup entirely for the vast majority of items.
**Action:** Always check if a pre-computed `HashSet` is available to safely skip expensive linear array traversals inside hot loops.
