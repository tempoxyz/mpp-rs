---
mpp: minor
---

Removed dependencies the library never used: `rand` (pulled in by `evm` and `utils`), `uuid` (pulled in by `tempo`, only used in tests) and `tokio-tungstenite` (pulled in by `ws`). The `sqlite` feature now enables `client`, where the SQLite channel store lives; before, `--features sqlite` alone compiled `rusqlite` without exposing the store.

Migration: the implicit `rand` and `uuid` cargo features are gone. If you enabled `mpp/rand` or `mpp/uuid`, drop them; they did not change the public API.
