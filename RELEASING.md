# Release preparation

The 0.13.0 candidate is local and unpublished. These commands build and verify
artifacts; they do not publish crates or create a GitHub release.

## Package layout

| Package | Candidate version | Role |
| --- | --- | --- |
| zinc-minreq | 0.1.0 | Blocking HTTP compatibility with a patched, client-local Rustls provider |
| zinc-esplora-client | 0.1.0 | Esplora client with Zinc request admission and current-state APIs |
| zinc-bdk-esplora | 0.1.0 | BDK adapter using the same explicitly named client |
| zinc-core | 0.13.0 | Wallet engine |

The helpers retain their upstream licenses and document differences in their
`ZINC-PATCH.md` files. They do not replace upstream crates globally. Normal
consumers need only `zinc-core`; consumers passing concrete Esplora client types
to Core must use the matching Zinc helper instead of the upstream client type.

## Local checks

Rust 1.88 is the library MSRV. Use Cargo 1.92 or newer for workspace packaging:
it stages the unpublished helper packages in a temporary local registry during
verification. Run from a clean checkout:

```sh
cargo fmt --all -- --check
cargo clippy -p zinc-core --locked --all-targets --all-features -- -D warnings
cargo test -p zinc-core --locked
cargo test -p zinc-minreq --locked --all-features --lib
cargo check --workspace --locked --all-features
cargo audit --deny warnings
cargo +1.88.0 check -p zinc-core --locked --lib --all-features
cargo package --workspace --locked
```

The resulting four archives are under `target/package/`. Do not bypass package
verification. Inspect their manifests and file lists for unwanted paths,
identities and secrets. Also run the WASM tests and production export audit in
`CONTRIBUTING.md`; native packaging alone does not qualify WASM or mobile builds.

Core's deterministic unit and mock-server tests remain public-source candidates.
The application release E2E harness is maintained separately. The inherited
Esplora daemon tests are opt-in (see that helper's patch note); no daemon binaries
are bundled or downloaded automatically by these packages.

## Eventual publication

Publishing requires a separate explicit decision. The dependency order is
`zinc-minreq`, `zinc-esplora-client`, `zinc-bdk-esplora`, then `zinc-core`. After each helper is
available from the registry, verify the next package against that registry.
Verify a new native and WASM consumer with no local paths or patch overrides.
Publish matching source and checksum artifacts to GitHub only after those checks.

This candidate has sanitized local Git history. A local metadata rewrite does
not remove old attribution from existing public copies. Resolve how to introduce
the sanitized history before moving any existing public branch or tag. Preserve
third-party copyright and contribution notices.
