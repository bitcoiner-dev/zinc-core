# Zinc BDK Esplora adapter

This is the Zinc-maintained `zinc-bdk-esplora` package, version 0.1.0 (unreleased
candidate). Upstream documentation is retained below for API context. Install
this package explicitly to use it with Zinc Core 0.13.0:

```toml
bdk_esplora = { package = "zinc-bdk-esplora", version = "=0.1.0" }
```

See [Zinc changes](ZINC-PATCH.md) for provenance, differences and test setup.
The upstream installation and release instructions below refer to upstream,
not to this candidate.

---

# BDK Esplora

BDK Esplora extends [`esplora-client`] (with extension traits: [`EsploraExt`] and
[`EsploraAsyncExt`]) to update [`bdk_chain`] structures from an Esplora server.

The extension traits are primarily intended to satisfy [`SyncRequest`]s with [`sync`] and
[`FullScanRequest`]s with [`full_scan`].

## Usage

For blocking-only:
```toml
bdk_esplora = { version = "0.19", features = ["blocking"] }
```

For async-only:
```toml
bdk_esplora = { version = "0.19", features = ["async"] }
```

For async-only (with https):

You can additionally specify to use either rustls or native-tls, e.g. `async-https-native`, and this applies to both async and blocking features.
```toml
bdk_esplora = { version = "0.19", features = ["async-https"] }
```

For async-only (with tokio):
```toml
bdk_esplora = { version = "0.19", features = ["async", "tokio"] }
```

To use the extension traits:
```rust
// for blocking
#[cfg(feature = "blocking")]
use bdk_esplora::EsploraExt;

// for async
#[cfg(feature = "async")]
use bdk_esplora::EsploraAsyncExt;
```

For full examples, refer to [`example_wallet_esplora_blocking`](https://github.com/bitcoindevkit/bdk/tree/master/examples/example_wallet_esplora_blocking) and [`example_wallet_esplora_async`](https://github.com/bitcoindevkit/bdk/tree/master/examples/example_wallet_esplora_async).

[`esplora-client`]: https://docs.rs/esplora-client/
[`bdk_chain`]: https://docs.rs/bdk-chain/
[`EsploraExt`]: crate::EsploraExt
[`EsploraAsyncExt`]: crate::EsploraAsyncExt
[`SyncRequest`]: bdk_core::spk_client::SyncRequest
[`FullScanRequest`]: bdk_core::spk_client::FullScanRequest
[`sync`]: crate::EsploraExt::sync
[`full_scan`]: crate::EsploraExt::full_scan
