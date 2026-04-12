## 2024-04-12 - Pre-allocating HashMaps for performance
**Learning:** Initializing `HashMap`s with `HashMap::new()` when processing a known, large collection of items (like `self.inscriptions`) leads to repeated dynamic reallocations which can hurt performance in loops during `psbt` signing or analysis.
**Action:** When creating a `HashMap` that will be populated from an existing array/vector of known size, use `HashMap::with_capacity(known_size)` to pre-allocate capacity and avoid resize overhead.
