## 2024-04-06 - Pre-allocate capacity for known_inscriptions HashMap
**Learning:** Pre-allocating `HashMap` size when iterating over a collection of known length prevents dynamic memory reallocations, improving execution speed and efficiency.
**Action:** Always consider using `HashMap::with_capacity` rather than `HashMap::new` when the upper bound of elements to be inserted is known or can be accurately estimated.
