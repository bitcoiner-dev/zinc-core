# Zinc Esplora extensions

Source: crates.io `esplora-client` 0.12.3, MIT (LICENSE retained).
The retained fork changes the async client, API types and blocking compatibility
surface. This is more than a transport hook; review the complete fork before
replacing it with a published upstream version.

The runtime `Sleeper` gains default no-op before-request/after-response hooks.
GET attempts and the single POST dispatch invoke them. Zinc's SyncSleeper
implements these using Core's shared origin scheduler; BDK's internal HTTP
calls therefore participate without reimplementing BDK or Esplora parsing.
No broadcast retries are added. Other sleepers retain upstream behavior.

The async client also provides fresh script-hash statistics, confirmed-history
pagination, bounded batched outspend reads, and request-scoped transaction and
outspend snapshots. Core's current-state and Activity code calls these extensions.
Removing the path patch without equivalent APIs fails package compilation.

This fork is packaged as `zinc-esplora-client` 0.1.0. The Rust library name is
still `esplora_client`; Cargo dependency aliases keep existing source imports
working. Core and `zinc-bdk-esplora` depend explicitly on this package. Consumers
do not need a `[patch]` table. It is a Zinc-maintained fork, not an official
Esplora Client release.

Upstream authors and the MIT notice are retained. The inherited in-crate
regtest suite is available via explicit `cargo test -p zinc-esplora-client --lib`
with `BITCOIND_EXE` and `ELECTRS_EXE` supplied by the caller. It is excluded from
automatic workspace library tests, and binary-download dependency features are
disabled. Core's mock-server contracts exercise Zinc's extensions without those
daemons. No production implementation was changed to introduce the new package.

The blocking HTTP client now uses the explicitly named `zinc-minreq` package
under its existing `minreq` dependency alias. Its Rustls backend is updated to
patched releases with a client-local crypto provider. Minreq 2 request/status/
proxy behavior is retained; the named package has a distinct Rust type identity.
See ../minreq/ZINC-PATCH.md for exact source provenance and the TLS-only patch.
