# Zinc transport hook

Source: crates.io `esplora-client` 0.12.3, MIT (LICENSE retained).
Only `src/async.rs` differs from the published implementation.

The runtime `Sleeper` gains default no-op before-request/after-response hooks.
GET attempts and the single POST dispatch invoke them. Zinc's SyncSleeper
implements these using Core's shared origin scheduler; BDK's internal HTTP
calls therefore participate without reimplementing BDK or Esplora parsing.
No broadcast retries are added. Other sleepers retain upstream behavior.

Consuming Cargo workspaces must repeat the path patch: dependency-level
`[patch]` tables are not inherited. Keep the native and WASM patches aligned.
