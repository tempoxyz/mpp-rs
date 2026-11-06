---
mpp: patch
---

Secured SQLite session databases before WAL creation and repaired permissions on existing sidecars. Newly created session directories are private on Unix.

Rejected symlinks during permission repair and `file:` URI database paths so permission checks apply to the actual database. Custom paths must be filesystem paths.
