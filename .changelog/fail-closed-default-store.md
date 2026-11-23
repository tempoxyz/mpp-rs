---
mpp: patch
---

Changed `Mpp::create` to return an error when a Tempo builder has no `store` and `MPP_ENV` or `NODE_ENV` is `production` or the server runs on a multi-instance platform (such as AWS Lambda, Cloud Run, Fly.io, Heroku, Railway, Render or Vercel), instead of keeping replay protection in per-instance memory, as mppx does. Pass a shared store, or `.store(Arc::new(MemoryStore::new()))` to keep instance-local replay protection; relays and local development are unaffected.
