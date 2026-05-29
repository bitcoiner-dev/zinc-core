## 2024-05-29 - Pre-allocate HashMaps for Inscription Mappings

**Learning:** When generating PSBT signatures and performing Ordinal Shield Audits, the codebase dynamically allocates HashMaps to store mappings of `(Txid, Vout) -> Vec<(String, u64)>` for inscriptions. Using the default `HashMap::new()` causes incremental re-allocations during insertion loops over `self.inscriptions`. The exact capacity needed is directly equivalent to `self.inscriptions.len()`. Also, removing a custom `bytes_to_lower_hex` method in favor of the external `hex` crate's `encode` makes the codebase leaner and slightly faster by leveraging optimized upstream routines.

**Action:** Replace `HashMap::new()` with `HashMap::with_capacity(self.inscriptions.len())` for `known_inscriptions` maps and utilize external `hex` crate to avoid hand-rolled string formatting loops for byte serialization.
