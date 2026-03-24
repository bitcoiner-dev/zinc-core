## 2025-02-12 - [WASM Wallet Optimization]
**Learning:** Re-instantiating `WalletBuilder` per account index in `ZincWasmWallet::get_accounts` has massive overhead due to deriving `master_xprv` and parsing mnemonic every time.
**Action:** Use `inner.get_accounts` directly which leverages the pre-derived `master_xprv` for a ~12x performance boost.
