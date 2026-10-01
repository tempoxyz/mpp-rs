---
mpp: patch
---

Fixed realm auto-detection reading `HOST` and `HOSTNAME`. Container runtimes set these per replica, so each replica signed challenges with its own realm and rejected credentials for challenges issued by the others. The variable list now matches mppx (`MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, `WEBSITE_HOSTNAME`). Deployments that relied on `HOSTNAME` now fall back to `"MPP Payment"` unless one of those is set; set `MPP_REALM` or call `.realm(...)` to keep the previous value.
