# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- No changes yet.

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
