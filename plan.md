1. **Analyze performance opportunity in `src/builder.rs`:**
   In the `sign_psbt` and `analyze_psbt` methods, `known_inscriptions` `HashMap` is being built by iterating over `self.inscriptions`. The `HashMap::new()` initialization does not specify capacity, which may result in multiple memory reallocations if `self.inscriptions` is large.

2. **Implement optimization:**
   Modify the instantiation of `known_inscriptions` to use `HashMap::with_capacity(self.inscriptions.len())`. This will prevent unnecessary resizing of the HashMap.

3. **Complete pre-commit steps:**
   Ensure proper testing, verification, review, and reflection are done by running tests and formatting checks.

4. **Submit PR:**
   Create a PR with a descriptive title starting with '⚡ Bolt:' and explaining the optimization.
