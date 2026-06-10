## 2024-06-10 - Hex Encoding Optimization
**Learning:** Manual loop string formatting `write!(&mut s, "{:02x}", b)` and mapping an iterator `digest.iter().map(|b| format!("{b:02x}")).collect()` for byte-to-hex string conversions are inefficient and create unnecessary formatting macro overhead, especially for fixed size payloads.
**Action:** Replace these operations with the optimized `hex::encode` function from the external `hex` crate, which maps bits to char directly. This speeds up execution without sacrificing readability.
