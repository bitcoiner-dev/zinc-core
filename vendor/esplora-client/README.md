# Zinc Esplora client

This is the Zinc-maintained `zinc-esplora-client` package, version 0.1.0 (unreleased
candidate). Upstream documentation is retained below for API context. Install
this package explicitly to use it with Zinc Core 0.13.0:

```toml
esplora-client = { package = "zinc-esplora-client", version = "=0.1.0" }
```

See [Zinc changes](ZINC-PATCH.md) for provenance, differences and test setup.
The upstream installation and release instructions below refer to upstream,
not to this candidate.

---

# rust-esplora-client

Bitcoin Esplora API client library. Supports plaintext, TLS and Onion servers. Blocking or async.

<p>
    <a href="https://crates.io/crates/esplora-client"><img alt="Crate Info" src="https://img.shields.io/crates/v/esplora-client.svg"/></a>
    <a href="https://github.com/bitcoindevkit/rust-esplora-client/blob/master/LICENSE"><img alt="MIT Licensed" src="https://img.shields.io/badge/license-MIT-blue.svg"/></a>
    <a href="https://github.com/bitcoindevkit/rust-esplora-client/actions/workflows/cont_integration.yml"><img alt="CI Status" src="https://github.com/bitcoindevkit/rust-esplora-client/actions/workflows/cont_integration.yml/badge.svg?branch=release/0.12.x"></a>
    <a href='https://coveralls.io/github/bitcoindevkit/rust-esplora-client?branch=master'><img src='https://coveralls.io/repos/github/bitcoindevkit/rust-esplora-client/badge.svg?branch=master' alt='Coverage Status' /></a>
    <a href="https://docs.rs/esplora-client"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-esplora--client-green"/></a>
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
    <a href="https://discord.gg/d7NkDKm"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
</p>

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.63.0.

To build with the MSRV you will need to pin dependencies:

```shell
bash ci/pin-msrv.sh
```
