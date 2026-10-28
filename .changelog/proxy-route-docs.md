---
mpp: minor
---

Added `RouteDocs` and `ServiceBuilder::route_with_docs` so proxy routes, paid or free, can declare a `summary` and an OpenAPI `requestBody` that `generate_openapi` emits in the proxy's `/openapi.json`. `Route` gains a `docs` field.
