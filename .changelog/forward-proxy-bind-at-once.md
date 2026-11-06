---
mpp: patch
---

Changed `ForwardProxy::bind` to return without loading the system's trusted roots, which took about 150 ms on macOS: `ForwardProxy::spawn` now loads them and writes the `certificates` bundle before it serves, so a caller learns `environment` at once and can run `spawn` off its startup path. Start child processes with `environment` once `spawn` returns, as before.
