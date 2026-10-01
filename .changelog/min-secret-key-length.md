---
mpp: minor
---

Fixed weak HMAC secrets being accepted: `Mpp::create` and `Mpp::create_stripe` now return `InvalidConfig` when `MPP_SECRET_KEY` or `.secret_key(...)` is shorter than 32 bytes, as mppx does. To migrate, generate a key with `openssl rand -base64 32` and set it as `MPP_SECRET_KEY`; challenges issued under the old key no longer verify, so clients holding one are challenged again. `Mpp::new` and the challenge helpers cannot fail and do not check the length.
