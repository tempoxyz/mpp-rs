---
mpp: patch
---

Secured SQLite session databases before WAL creation and repaired permissions on existing sidecars. Newly created session directories are private on Unix.

Rejected symlinks during permission repair and `file:` URI database paths so permission checks apply to the actual database. Custom paths must be filesystem paths.

Avoided changing permissions through hard links. Already-private regular files need no repair; root can still repair singly linked files owned by another user.

Pinned the repaired inode on Linux to prevent hard-link replacement races. Other Unix systems require a trusted parent directory for repairs and operate relative to its pinned descriptor without opening SQLite data files.
