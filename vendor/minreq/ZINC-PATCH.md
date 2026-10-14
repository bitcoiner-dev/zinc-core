# Zinc Minreq TLS compatibility patch

Source: published `minreq` 2.14.1, archive SHA-256
`05015102dad0f7d61691ca347e9d9d9006685a64aefb3d79eecf62665de2153d`.
The original ISC copyright and grant in COPYING.md are preserved.

This is packaged as `zinc-minreq` 0.1.0 with the Rust library name `minreq`.
Zinc Esplora uses a Cargo dependency alias; this is a Zinc-maintained fork,
not an official Minreq release. Consumers need no global Cargo patch table.

Only the Rustls transport source is changed: migrate from Rustls 0.21 to
patched Rustls 0.23, use current certificate/root types, and choose the Ring
provider explicitly for this client. Provider selection does not install or
replace a process-global provider. Configuration errors propagate through the
existing RustlsCreateConnection error. Ordinary certificate validation, server
name checks, bundled/system trust-root modes, TLS 1.2/1.3 and no-client-auth
behavior remain in place. No permissive certificate verifier is introduced.

This retains Minreq 2's status, headers, errors, request/proxy interfaces and
default proxy port 8080. A migration to upstream Minreq 3 would also change
those contracts and still needs an explicit provider when combined with Core.
The named crate has a distinct Rust type identity from upstream Minreq;
consumers of raw request/error types must use this package under the alias.

Rustls requires at least 0.23.45 and WebPKI at least 0.103.13. Native certificate
loading and root dependencies are migrated accordingly. The package uses Zinc's
Rust 1.88 floor. Original upstream source and documentation otherwise remain
unchanged; this patch is not a general HTTP-client security audit.
