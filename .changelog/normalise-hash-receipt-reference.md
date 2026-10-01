---
mpp: patch
---

Fixed Tempo charge receipts for hash credentials echoing the transaction hash as the client spelled it. A hash sent in upper case or without the `0x` prefix was verified but returned unchanged as the receipt `reference`; the reference is now always the lower-case `0x`-prefixed hash, as it already was for transaction credentials.
