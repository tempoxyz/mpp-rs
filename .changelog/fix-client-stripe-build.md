---
mpp: patch
---

Fixed the build with `--no-default-features --features client,stripe`, which failed because `protocol::methods` was only compiled with `server` or `tempo`. The Stripe client types are now available with `stripe` alone.
