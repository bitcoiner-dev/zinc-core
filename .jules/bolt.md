## 2024-12-07 - Pre-allocate HashMap using `.len()` from source collection

**Learning:** During large iterations building index mappings (like grouping inscriptions by `(Txid, Vout)`), standard `HashMap::new()` requires multiple dynamic reallocations. Since the number of unique items is upper-bounded by the source array size, we can pre-allocate memory to optimize loop performance.
**Action:** Always check the length of the source collection (e.g. `self.inscriptions.len()`) and use `HashMap::with_capacity(len)` when constructing new grouping mappings to avoid expensive memory reallocations during large loops.
