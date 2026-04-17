# zinc-core

<p align="center">
  <img src="https://raw.githubusercontent.com/bitcoiner-dev/zinc-core/main/assets/zinc-marquee.jpg" alt="Zinc" width="100%">
</p>

`zinc-core` is a Rust wallet engine for Bitcoin + Ordinals use cases.

Key capabilities:
- **Ledger Hardware Wallet Integration**: Full signing and verification flow for external hardware devices.
- **Watch-Only Identity**: Track and monitor any Taproot address without requiring private keys.
- **Parallel Account Probing**: High-performance battery-efficient probing of multiple account paths via WASM.
- **Deterministic Derivation**: Robust account/key derivation built on top of BDK.
- **Ordinal Shield Integration**: Integrated PSBT analysis for burn and movement risk detection.
- **Unified & Dual Schemes**: Flexible support for both unified taproot and distinct SegWit payment branches.

## Installation

```toml
[dependencies]
zinc-core = "0.3.0"
```

## What You Get

- BIP-39 mnemonic generation, validation, and encryption/decryption
- **Hardware Integration**: Support for Ledger and other hardware signatures via PSBT preparation and verification
- **Watch-Only Support**: Initialize wallets from public addresses for tracking-only functionality
- **Discovery Engine**: High-performance parallel probing for accounts across standard and legacy paths
- Taproot descriptor-based wallet construction with unified and dual-account address schemes
- Native sync with Esplora and Ordinals protection/analysis
- Typed surface for PSBT analysis and Ordinal Shield safeguards
- Extensible WASM exports for both stateless helpers and stateful wallet lifecycle

## Quick Start (Native Rust)

```rust
use zinc_core::{AddressScheme, Network, WalletBuilder, ZincMnemonic};

fn main() -> Result<(), String> {
    // Example mnemonic for development/testing only.
    let mnemonic = ZincMnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .map_err(|e| e.to_string())?;
    let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic)
        .with_scheme(AddressScheme::Unified)
        .build()?;

    let taproot = wallet.next_taproot_address()?;
    let payment = wallet.get_payment_address()?; // Unified: same taproot branch family

    println!("taproot: {taproot}");
    println!("payment: {payment}");
    Ok(())
}
```

## Address Model

- Canonical public naming uses `taproot*` fields and methods.
- In `Unified` mode, payment role resolves to the same taproot key/address family.
- In `Dual` mode, payment role uses a distinct SegWit payment branch.

## Constructor Model

- `WalletBuilder::from_mnemonic(network, &mnemonic)`
- `WalletBuilder::from_seed(network, seed64)`

## Example Programs

Run from the workspace root (`wallet/zinc-core`):

```bash
cargo run -p zinc-core --example wallet_setup
cargo run -p zinc-core --example psbt_sign_audit
ESPLORA_URL=https://mempool.space/api \
  cargo run -p zinc-core --example sync_and_balance
```

- `wallet_setup.rs`: deterministic setup + account/address inspection
- `sync_and_balance.rs`: online sync flow and balance retrieval
- `psbt_sign_audit.rs`: Ordinal Shield analysis over a sample PSBT

## WASM Integration Notes

WASM exports include:
- **Stateless helpers**: `generate_wallet`, `validate_mnemonic`, `derive_address`, `encrypt_wallet`, `decrypt_wallet`
- **Stateful handles**: `ZincWasmWallet` (supports Mnemonic, Watch, and **Hardware** profiles)
- **Discovery**: `probeHardwareAccounts` for ultra-fast parallel account scanning
- **Hardware Signing**: `prepareExternalSignPsbt` and `verifyExternalSignedPsbt`
- **Analytics**: `analyzePsbt` for integrated Ordinal Shield protection
- **Logging**: `set_log_level`, `set_logging_enabled`, `get_log_level`

`init()` installs panic hooks only. Host applications should configure their own log subscriber/sink.

## Logging Model

- Default runtime level is `warn`
- Runtime levels accepted by WASM API: `off|error|warn|info|debug|trace`
- Identifier-rich diagnostics (for example tx/output identifiers) are intended for `debug`

## Security and Stability

- This is security-sensitive software. Review release notes before upgrading.
- Avoid logging secret material and mnemonic data.
- Reporting process: see [SECURITY.md](./SECURITY.md).
- Discovery APIs are hardened to avoid exposing raw master private keys.

## Development Checks

```bash
cargo fmt --all -- --check
cargo clippy -p zinc-core --all-targets --all-features -- -D warnings
cargo test -p zinc-core --locked
cargo doc -p zinc-core --no-deps
```

## License

Licensed under MIT. See [LICENSE](./LICENSE).
