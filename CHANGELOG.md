# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-04-17

### Added
- Ledger Hardware Wallet integration including `prepareExternalSignPsbt` and `verifyExternalSignedPsbt` WASM APIs.
- Watch-only address support via `new_watch_address`, enabling monitoring of any Taproot address without private keys.
- High-performance parallel account probing WASM API (`probeHardwareAccounts`) for rapid hardware wallet discovery.
- Support for "Dual" address schemes and comprehensive legacy path discovery.

### Fixed
- Resolved hardware wallet hydration and descriptor parsing inconsistencies.
- Fixed dual payment signing descriptors for Segwit applications.
- Eliminated various compilation warnings related to dead code and unnecessary mutability.
- Gated architecture-specific test imports to resolve unused import warnings.

### Changed
- Unified internal wallet material handling across Seed, Watch, and Hardware profiles.
- Upgraded core BDK dependencies to improve PSBT enrichment and derivation handling.

## [0.2.0] - 2026-04-07

### Added
- High-integrity Sign-Intent system for hardened wallet pairing and signing transport.
- Initial Runes protocol support including read operations and parser updates.
- Enhanced WASM bindings including `discoverImportPath` and granular derivation controls.

### Fixed
- Resolved Ordinal Shield panic risks and enforced stricter "main-address" scan policies.

### Changed
- Refined core APIs to support explicit derivation mode and payment address type controls.


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
