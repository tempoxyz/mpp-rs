---
mpp: minor
---

Breaking: changed handlers from `Mpp::create` without a `store` to log a warning and refuse to issue or verify Tempo charges when `MPP_ENV` or `NODE_ENV` is `production` or a platform variable (`AWS_LAMBDA_FUNCTION_NAME`, `DENO_DEPLOYMENT_ID`, `DYNO`, `FLY_APP_NAME`, `K_SERVICE`, `NETLIFY`, `RAILWAY_ENVIRONMENT`, `RENDER` or `VERCEL`) is set, instead of keeping replay protection in per-instance memory, as mppx does; sessions and relays are unaffected. Other multi-instance deployments, such as Kubernetes, are not detected and must pass a shared store, and `.store(Arc::new(MemoryStore::new()))` keeps instance-local replay protection.
