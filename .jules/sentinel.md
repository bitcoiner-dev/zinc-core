## 2024-05-18 - [CRITICAL] Fix unwrap panics in BIP32 derivation paths
**Vulnerability:** Found uses of `.unwrap()` on `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` within `ZincWallet` methods `sign_message`, `sign_inscription_script_paths`, and `get_key`. This can cause a panic and Denial of Service (DoS) in the application or WASM runtime if an invalid child index (>= 2^31) is ever supplied via external state or input.
**Learning:** `ChildNumber::from_hardened_idx` and `ChildNumber::from_normal_idx` return a `Result` that panics when unwrapped if the index is out of range.
**Prevention:** Avoid using `.unwrap()` on BIP32 path derivation components. Map the error and propagate it securely using `?`.
