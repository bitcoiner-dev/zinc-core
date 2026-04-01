## 2024-05-14 - Fast Path Checks

**Learning:** When adding fast-path checks to skip expensive operations inside a loop (e.g., using `continue` after checking a `HashSet`), ensure you only skip the specific expensive sub-task. Broadly skipping the entire loop iteration can cause unintended functional regressions by omitting baseline data processing (like omitting regular transactions when checking for inscriptions).

**Action:** Be mindful of where early returns and loop continuations are placed. Use `self.inscribed_utxos` (a HashSet) for O(1) fast-path checks to determine if a transaction output contains an inscription. This avoids expensive linear searches through the `self.inscriptions` vector during iterations.
