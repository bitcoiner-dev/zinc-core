# Changelog

All notable changes to this project will be documented in this file.

## [0.7.0] - 2026-07-07

### Added
- Runes protocol support for the Ordinal Shield: runestone/cenotaph decoding via
  the canonical `ordinals` crate and rune allocation simulation matching ord's
  `RuneUpdater` semantics (`ordinals::runes` module).
- `analyze_psbt_with_context` + `ShieldContext`/`KnownRunes`: rune-aware PSBT
  analysis with per-input/per-output `RuneAmount` annotations, a `RuneActions`
  summary (etch/mint/edicts/cenotaph/burns), warning escalation (rune burns and
  cenotaphs are `Danger`), fee-rate estimation (`fee_rate_sat_vb`), and dust
  flags. The placeholder rune id `"0:0"` denotes the rune being etched by the
  analyzed transaction.
- `OrdClient::get_rune_info` (`/rune/<id-or-name>`) and per-outpoint rune
  holdings on `ResolvedAssets` (`outpoint_runes`, `rune_infos`), joined
  name→ID at sync time and failing closed when a rune id cannot be resolved.
- Wallet: `apply_outpoint_rune_holdings`, `rune_info`/`cache_rune_infos`,
  `UtxoItem.runes`; `analyze_psbt` now runs with full rune context and applies
  descriptor-true `is_mine`/`is_change` plus rune display metadata.
- WASM: `resolveRuneInfo(ordUrl, ids)` returning `{ resolved, failed }`;
  `syncOrdinals` threads rune holdings through.
- `RuneBalance` gains an optional canonical `id`.

### Changed
- **Breaking (struct literals):** `AnalysisResult`, `InputInfo`, `OutputInfo`,
  `RuneBalance`, `ResolvedAssets`, and `UtxoItem` gained fields; struct-literal
  construction must be updated. Serialized wire shapes remain backward
  compatible (new fields are optional/defaulted).
- MSRV raised from 1.77 to 1.80 (required by the `ordinals` dependency).

## [0.6.0] - 2026-07-06

### Added
- Address-level dApp role candidates for Sparrow / `ord` wallet profiles, including
  clean BTC sats, protected asset counts, inscription ids, derivation details, and
  core-owned payment/ordinals eligibility.
- WASM APIs `getDappAddressCandidates` and `confirmDappAddressSelection` for safe
  dApp connect flows that bind explicit BTC and collectibles addresses.

### Changed
- Extended wallet address scanning/classification so Sparrow / `ord` profiles can
  distinguish clean spendable BTC, inscription-only taproot addresses, empty taproot
  addresses, and mixed unsafe addresses.

## [0.5.0] - 2026-06-28

### Added
- CPFP anchor output support for listing purchases.
- `next_unused_taproot_address` for Sparrow / `ord` receive workflows.

### Changed
- **Breaking:** `ZincWallet::prepare_requests` now takes a `force_full: bool` argument.
- **Breaking:** `FinalizeListingPurchaseRequest` gains an `anchor_output` field and
  `FinalizeListingPurchaseResultV1` gains an `anchor_output_index` field; struct-literal
  construction of these types must be updated.

### Fixed
- **Security:** hardened BIP-32 child-key derivation so out-of-range derivation indices
  return an error instead of panicking and aborting the WASM runtime; added safe handling
  of taproot signature parsing and Ordinal-Shield output-index conversion.
- Corrected multi-inscription salvage sat-tracking.

### Performance
- Replaced the hand-rolled hex encoder with `hex::encode`; pre-sized inscription lookup maps.

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
