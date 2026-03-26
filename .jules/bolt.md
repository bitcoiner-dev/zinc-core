## 2024-03-26 - [Fast-path for Inscription Lookups]
**Learning:** Checking for inscriptions on transaction outputs can be an O(N*M) bottleneck when iterating over all outputs and comparing them against a list of known inscriptions. Using a pre-computed HashSet of inscribed outpoints (`inscribed_utxos`) allows an O(1) fast-path to skip the O(M) search for non-inscribed outputs.
**Action:** Use fast-path early returns when iterating over collections, especially when there's an O(1) check available to avoid more expensive lookups or computations.
