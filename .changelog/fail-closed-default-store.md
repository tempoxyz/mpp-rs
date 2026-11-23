---
mpp: minor
---

Breaking: changed handlers from `Mpp::create` to fail closed, returning an error when they issue or verify a Tempo charge without a `store` while `MPP_ENV` or `NODE_ENV` is `production` or the server runs on a multi-instance platform (such as AWS Lambda, Cloud Run, Fly.io, Heroku, Railway, Render or Vercel), instead of keeping replay protection in per-instance memory, as mppx does. Pass a shared store, or `.store(Arc::new(MemoryStore::new()))` to keep instance-local replay protection; sessions, relays and local development are unaffected.
