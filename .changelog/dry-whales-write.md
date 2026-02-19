---
mpp: patch
---

Added auto-detection of `realm` from environment variables in `Mpp::create()`. Checks `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, and `WEBSITE_HOSTNAME` in order, falling back to `"MPP Payment"`.
