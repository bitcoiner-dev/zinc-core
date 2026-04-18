## 2024-05-16 - Prevent Panic DoS from Unbound Child Derivation Index

**Vulnerability:** Core builder operations like `derive_public_key_internal` called `.unwrap()` directly on `ChildNumber::from_hardened_idx` and `from_normal_idx`. These calls panic if provided an integer `u32` value greater than `0x80000000` (the hardened boundary marker limit).
**Learning:** Even internal API inputs must be thoroughly bounds-checked if they influence the derivation tree boundaries, otherwise it opens up Denial of Service attacks when consuming downstream libraries that surface this to untrusted users or configuration paths.
**Prevention:** Always use safe wrapper methods to convert bounds errors into expected `Result` strings and use `?` operator over `unwrap()` when dynamically determining key derivation paths.
