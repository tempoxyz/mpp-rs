---
mpp: patch
---

Added `SqlStore`, an atomic server `Store` on Postgres (`postgres-store`, tokio-postgres) or SQLite (`sqlite-store`, rusqlite) that keeps values in one `mppx_store` table and makes every write a single statement, as mppx's `Store.sql()` does. `SqlStore::purge_expired` deletes expired claims.
