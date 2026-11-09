---
mpp: patch
---

Fixed session bootstrap recovery to require an explicitly configured origin before importing unknown channels. Stopped unsigned snapshot amounts from increasing recovered payment authorization.

Updated bundled SQLite to a patched release that rejects mismatched database and WAL page sizes.
