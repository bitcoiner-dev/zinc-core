# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- No changes yet.

## [0.1.2] - 2026-03-27

### Fixed
- Improved deep account discovery reliability by scanning receive addresses beyond index 0, reducing false negatives during wallet restore.

### Changed
- `discoverAccounts` now accepts optional `address_scan_depth` and `timeout_ms` controls with safe defaults.
- Added batched receive-scan coverage tests for account discovery behavior.

## [0.1.1] - 2026-03-26

### Changed
- Bumped crate version to `0.1.1` for release alignment.

## [0.1.0] - 2026-03-16

### Added
- Initial public release of `zinc-core`.
- Explicit-network constructors:
  - `WalletBuilder::from_seed(network, seed64)`
  - `WalletBuilder::from_mnemonic(network, mnemonic)`
- Typed core request/error surface for PSBT construction:
  - `CreatePsbtRequest`
  - `ZincWallet::create_psbt_tx(&CreatePsbtRequest) -> Result<Psbt, ZincError>`
- Discovery-context APIs that avoid exposing raw master private keys.
- Public open-source documentation and policy files.

### Changed
- Canonical public naming uses `taproot*` across public Rust and WASM surfaces.
- Unified mode payment role maps to the same taproot address/public-key family (not unsupported).
- WASM payloads are canonicalized to `taproot*` fields.
- Wallet internals were narrowed to reduce external mutation surface.
- Wallet discovery APIs hardened to avoid raw `Xpriv` exposure.
- Crate metadata and package include/exclude lists updated for `crates.io` readiness.
