---
mpp: minor
---

Added `ForwardProxy` behind the `forward-proxy` feature: a local HTTP forward proxy that lets programs that know nothing about MPP, such as `curl`, pay for MPP services. It terminates TLS for the origins its `AcceptPaymentPolicy` allows with certificates from a per-process certificate authority, pays `402` challenges with a provider per origin, retries and streams the response back, and tunnels every other host untouched. `ForwardProxy::environment` returns the proxy and trust variables for child processes, and `directory::service_urls` fetches the services listed in an MPP directory such as mpp.dev's.
