## 2024-11-20 - Fast Hex Encoding

**Learning:** Generic standard formatting inside a loop (`write!(&mut s, "{:02x}", b)`) introduces significant overhead compared to direct optimized libraries for operations like hex encoding. This overhead scales linearly per byte and adds unnecessary CPU usage during serialization tasks.
**Action:** Always prefer using specialized parsing/formatting tools (like `hex::encode`) over looping generic formatters when optimizing for CPU time, especially inside hot loops or serialization tasks.
