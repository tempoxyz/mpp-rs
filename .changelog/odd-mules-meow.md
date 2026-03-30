---
mpp: patch
---

Fixed a race condition in `ChannelStoreAdapter` where concurrent `update_channel` calls for the same channel could overwrite each other. Added per-channel async mutex locking to serialize read-modify-write operations within a single process, along with tests reproducing the original race.
