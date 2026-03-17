# zinc-core

`zinc-core` is a Rust wallet engine for Bitcoin + Ordinals use cases.

Key capabilities:
- deterministic account/key derivation on top of BDK,
- taproot-first public API naming,
- transaction creation/signing/broadcast helpers,
- Ordinal Shield PSBT analysis (burn/movement risk detection),
- optional WASM bindings for browser and extension hosts.

## Installation

```toml
[dependencies]
zinc-core = "0.1"
```

## What You Get

- BIP-39 mnemonic generation, validation, and seed derivation
- Explicit-network wallet constructors (`from_mnemonic`, `from_seed`)
- Taproot descriptor-based wallet construction
- Unified and dual-account address schemes
- Native sync with Esplora backends
- Ordinals protection + metadata sync and PSBT analysis
- Typed core request/error surfaces (`CreatePsbtRequest`, `ZincError`)
- WASM exports for wallet lifecycle and runtime log controls

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
- stateless helpers: `generate_wallet`, `validate_mnemonic`, `derive_address`, `encrypt_wallet`, `decrypt_wallet`
- stateful wallet wrapper: `ZincWasmWallet`
- runtime logging controls: `set_log_level`, `set_logging_enabled`, `get_log_level`

WASM payloads are canonicalized to `taproot*` keys.

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
