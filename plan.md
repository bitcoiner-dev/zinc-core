1. **Analyze `known_inscriptions` capacity pre-allocation.**
   - `known_inscriptions` `HashMap` is populated using `self.inscriptions` length as an upper bound on capacity in `src/builder.rs` and `src/lib.rs`.
   - By pre-allocating the `HashMap` with `self.inscriptions.len()`, we can avoid expensive dynamic reallocations during large loops.
   - e.g., `let mut known_inscriptions: HashMap<_, _> = HashMap::with_capacity(self.inscriptions.len());`

2. **Run format/linters/tests**
   - Execute `cargo fmt`, `cargo test`, and `cargo clippy` to ensure changes are correct and don't introduce regressions.

3. **Pre-commit step**
   - Ensure proper testing, verification, review, and reflection are done.

4. **Submit PR**
   - Create a PR with title "⚡ Bolt: pre-allocate known_inscriptions map capacity"
