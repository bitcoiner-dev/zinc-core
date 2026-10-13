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

Consuming Cargo workspaces must repeat the path patch: dependency-level
`[patch]` tables are not inherited. Keep the native and WASM patches aligned.
