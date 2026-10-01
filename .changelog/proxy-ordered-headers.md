---
mpp: minor
---

Fixed the proxy injecting upstream headers in a random order. `proxy::Service::headers` was a `HashMap`, so the order changed from run to run, and `bearer(..)` followed by `header("authorization", ..)` kept both entries and let either one win. Headers are now injected in the order they were added, and adding a name again (in any letter case) replaces the earlier value.

Migration: `Service::headers` is now a `Vec<(String, String)>`. Replace `service.headers.get(name)` with `service.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))`.
