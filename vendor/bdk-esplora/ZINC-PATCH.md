# Zinc BDK Esplora adapter

Based on the published `bdk_esplora` 0.22.3 source, licensed MIT OR Apache-2.0.
Both upstream license texts are retained. This is a Zinc-maintained package,
not an official Bitcoin Dev Kit release.

The adapter retains upstream behavior; one `map_or(true, ...)` expression uses
the equivalent `is_none_or(...)` spelling for the workspace's lint checks. The package is named
`zinc-bdk-esplora`; its `esplora-client` dependency is explicitly aliased to
`zinc-esplora-client` 0.1.0. This keeps the adapter and Core on the same client
type without a consuming workspace's `[patch]` table. The library import remains
`bdk_esplora` for source compatibility.

The upstream daemon-based integration harness is not included in this adapter
package. Core's deterministic backend/current-state contracts exercise this
adapter with its actual Zinc client. Neither this package nor its build scripts
download or start Bitcoin or Electrs daemons.
