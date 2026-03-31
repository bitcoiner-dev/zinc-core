## 2024-03-31 - [Optimize PSBT enrichment]
**Learning:** Checking for early return conditions (e.g. `has_missing_utxos` in PSBT enrichment) before executing expensive O(N) loops (`list_unspent()`) can yield significant performance boosts in core wallet operations like `sign_psbt` and `analyze_psbt`.
**Action:** When implementing routines that enrich partial data by scanning a large underlying state (like a wallet's UTXO set), always check if the enrichment is actually required first.
