---
mpp: patch
---

Fixed a security issue where a POST request to a free GET endpoint could bypass payment requirements via the method-mismatch fallback path. Introduced `match_route_path_only_paid` to exclude free routes from the fallback, and updated tests accordingly.
