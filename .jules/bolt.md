## 2024-04-08 - Fast-path cache lookups for Inscriptions
**Learning:** Found that using an O(1) HashSet (`self.inscribed_utxos`) cache to quickly filter out outpoints before falling back to linear O(N) array search on `self.inscriptions` within large loops greatly improves algorithm performance for heavy workloads. Also, pre-allocating HashMap bounds for known-sized inputs avoids memory-hungry realocations.
**Action:** Consistently leverage HashSets and `HashMap::with_capacity` mappings for critical path lookups.
