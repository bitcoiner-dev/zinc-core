# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.10.0] - 2026-08-08

### Added
- Versioned, vendor-neutral external-signer capability negotiation. Zinc now
  derives input, output, sighash, signing-scope, and device-limit requirements
  from the exact prepared PSBT and compares them with adapter-supplied effective
  capabilities.
- Typed compatibility reports and rejection codes for native and WASM hosts,
  including stable capability keys such as `output.runestone`.
- `prepare_external_signing_request` / `prepareExternalSigningRequest`, which
  combines the existing PSBT safety preparation with mandatory capability
  enforcement before a transaction can be dispatched to a device.

### Security
- Runestone outputs are detected from their exact `OP_RETURN OP_13` script
  prefix and kept distinct from ordinary push-data `OP_RETURN` outputs. A signer
  must explicitly advertise Runestone representation support; otherwise the
  request is rejected before device I/O.

### Changed
- **Breaking:** remove the deprecated positional Rust/WASM `create_psbt` APIs;
  hosts must use the typed `createPsbt(request)` contract.
- **Breaking:** remove the retired `vault` / `vaultPublicKey` address aliases and
  `vaultAddress` / `vaultPublicKey` account-input aliases.
- **Breaking:** stop emitting and accepting the non-standard Nostr `expires` tag;
  offer and listing events use NIP-40 `expiration` exclusively.
- **Breaking:** reject password-vault format v1. Password-encrypted secrets use
  v2; seed vaults should use the hardware-keystore v3 format.
- Remove the crates.io public-API SemVer compatibility gate while Zinc remains
  pre-release and has no external consumers.

## [0.9.0] - 2026-08-03

### Security
- **Breaking:** remove the `generate_wallet` WebAssembly export. Wallet shells must
  use their dedicated, auditable seed-generation boundary instead of asking the
  broad wallet engine to generate a mnemonic.
- **Breaking:** remove the unused native `sign_bip322_simple_hex` helper and its
  `bip322` dependency. BIP-322 signing should be introduced through an explicit
  wallet-signer boundary when a supported application flow requires it.

## [0.8.0] - 2026-07-23

### Added
- **Breaking:** fractional fee rates — `f64` sat/vB end-to-end (transport,
  planners, analysis, wasm surface) with kwu-precision fee math, so sub-1 sat/vB
  regimes are representable exactly. Integer-only call sites must switch to
  floats; serialized shapes accept both.
- Version-3 hardware-keystore vault format: the seed is encrypted under a random
  256-bit data-encryption key used directly as the AES-256-GCM key — no
  password derivation — so the DEK can live in the platform hardware keystore
  (Secure Enclave / Android Keystore) and a leaked vault blob cannot be
  brute-forced offline. New wasm seam: `generate_vault_key`,
  `encrypt_wallet_with_key`, `decrypt_wallet_with_key`. v1/v2 vaults remain
  readable; v3 and v1/v2 refuse to decrypt each other's blobs.
- Golden-file PSBT determinism tests for the deterministic planners, and
  BIP-32/39/86 known-answer vectors with a taproot differential check pinning
  key derivation to the published specs.

### Changed
- **Breaking:** shield analysis surfaces `ordinals_verified` as
  `assets_verified` (it now covers runes as well as inscriptions).
- **Breaking:** `prepare_offer_acceptance` takes the accepting wallet's expected
  payout scriptPubKey (see Security).
- `layout::BranchSpec` drops its redundant `purpose` field; rune edict/output
  amount handling reworked.

### Security
- Taproot script-path signing binds every leaf to the prevout being spent: the
  control block must commit to the prevout's taproot output key. Previously
  `sign_inscription_script_paths` signed every `tap_scripts` leaf without
  checking the control block — a blind script-path signing oracle reachable
  through a dapp's `signPsbt`. Regression-tested (mutation-verified).
- Shield analysis accumulates ordinal sat offsets across **all** inputs, not
  just the scoped ones, so a partial-sign (`signInputs: [n]`) analysis can no
  longer report a burned inscription as safe. Regression-tested
  (mutation-verified).
- Declared prevouts are verified instead of blanket-trusted: a PSBT
  `witness_utxo`/`non_witness_utxo` that contradicts our own chain data is
  refused, non-taproot inputs require full prevout proof (legacy sighash does
  not commit to amounts — fee-inflation defense), and
  `trust_witness_utxo` is computed per PSBT instead of hardcoded on.
- Offer flow: `create_offer` routes the seller payout to the seller instead of
  back to the buyer (the previous rule was exactly inverted), and offer
  acceptance binds the payout output to the accepting wallet's own script so a
  hostile offer cannot redirect it.
- The Nostr pairing identity now derives from a non-spending branch
  (`m/86'/coin'/account'/2/0`) instead of the primary spending key, so an
  observer of pairing traffic can no longer derive the wallet's funded address
  and read its balance/history. The secret is `Zeroizing` on drop.
  **Migration:** previously-paired agents hold the old identity and must
  re-pair.

## [0.7.0] - 2026-07-23

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
- Derivation-layout module (`layout::BranchSpec`,
  `WalletBuilder::with_layout`) so wallet shells can describe account-discovery
  layouts explicitly.
- `enrich_psbt_key_origins` on the builder: key-origin metadata for external
  (hardware) signers.
- Safe, ord-compatible rune transfer planning.
- `chain_tip_height` and `mark_ordinals_unverified` accessors.

### Changed
- **Breaking (struct literals):** `AnalysisResult`, `InputInfo`, `OutputInfo`,
  `RuneBalance`, `ResolvedAssets`, and `UtxoItem` gained fields; struct-literal
  construction must be updated. Serialized wire shapes remain backward
  compatible (new fields are optional/defaulted).
- MSRV raised from 1.77 to 1.80 (required by the `ordinals` dependency).

### Fixed
- Sync: primary-address script pubkeys are always revealed at wallet
  construction/reset, so incremental syncs discover funds and inscriptions sent
  to the primary address; per-network changeset scoping prevents cross-network
  cache wipes; verified-empty guards stop transient ord outages from
  unverifying held assets.
- `plan_consolidate_tx` engages the ordinals safety lock.
- Repaired pre-existing wasm-test breakage.

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
