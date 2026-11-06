---
mpp: patch
---

Secured SQLite session databases before WAL creation and repaired permissions on existing sidecars. Newly created session directories are private on Unix.

Rejected symlinks during permission repair and `file:` URI database paths so permission checks apply to the actual database. Custom paths must be filesystem paths.

Avoided changing permissions through hard links. Already-private regular files need no repair; root can still repair singly linked files owned by another user.

Pinned the parent directory for permission repair on every Unix platform. Repairs require a directory owned by the effective user and not writable by group or others. Directory-relative checks reject symlinks and hard links without opening SQLite data files or relying on Linux-specific chmod support. Already-private regular files do not require repair.
