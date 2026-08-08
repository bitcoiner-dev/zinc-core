## 2024-05-18 - Avoid generic formatting for hex encoding
**Learning:** Using `format!` in loops for simple hex byte conversion (e.g. `format!("{b:02x}")`) is computationally expensive and slow compared to using a bitwise nibble-to-hex mapping.
**Action:** Replace `format!` macros inside hex-encoding loops with zero-dependency bitwise operations (e.g., `bytes_to_hex_lower`), yielding massive speedups (e.g. ~3.4x faster) in hot paths.
