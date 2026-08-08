# Contributing

Thanks for helping improve `zinc-core`.

## Development Setup

1. Install stable Rust.
2. From the workspace root (`wallet/zinc-core`), run:

```bash
cargo fmt --all -- --check
cargo test -p zinc-core
cargo check --no-default-features
cargo check --features debug
cargo clippy -p zinc-core --all-targets --all-features -- -D warnings
cargo doc -p zinc-core --no-deps
cargo package --allow-dirty
```

WASM changes also require a wasm-capable clang and:

```bash
wasm-pack test --node . --test wasm_test --test wasm_account_test --test wasm_contract_test
wasm-pack build --target web --release --out-dir target/wasm-audit
node scripts/audit-wasm-exports.mjs target/wasm-audit/zinc_core_bg.wasm
```

## Pull Requests

- Keep changes focused and well-scoped.
- Add or update tests for behavior changes.
- Update docs/examples if public APIs or user workflows change.
- Document user-visible changes in `CHANGELOG.md`.
- Do not add compatibility aliases or readers for unpublished APIs without a
  concrete downstream consumer and explicit review. Breaking pre-release cleanup
  should remove the obsolete surface completely.

## Security-Sensitive Code

Changes related to key handling, signing, or transaction safety should include:

- threat/abuse scenario coverage,
- explicit test coverage, and
- careful review of failure paths.

In particular:

- Secret-owning Rust values should use zeroizing owners where practical. Review
  intermediate strings/vectors, error formatting, serialization, and `Debug`
  implementations—not only the originating buffer.
- Hardware/watch-only constructors must reject private descriptors and keys.
- Persistent BDK wallets must remain watch-only. Software signer containers may
  exist only within an authorized signing call, and lock paths must scrub the
  master key and prove that later signing fails closed even through an older
  reachable BDK handle.
- New or removed WASM exports must pass this repository's production export audit.
  The downstream Zinc repository additionally maintains an exact normalized
  import/export manifest, so intentional capability changes require a reviewed
  manifest update there.
- Avoid claims of complete memory erasure across JavaScript, IPC, WASM linear
  memory, compiler temporaries, or a compromised process; state the narrower
  property that tests actually enforce.
