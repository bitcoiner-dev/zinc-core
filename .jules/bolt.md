## 2024-03-27 - O(1) Fast Path for Inscription Details
**Learning:** Checking inscription existence on an output previously did an O(N) scan over `self.inscriptions` (which could be large). `self.inscribed_utxos` is a HashSet designed specifically to make this check O(1).
**Action:** Use `self.inscribed_utxos.contains(&outpoint)` as a fast-path filter before performing the linear search in `get_inscription_details`.
