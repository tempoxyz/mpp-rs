---
mpp: patch
---

The prebuilt OpenAI proxy service now strips caller-supplied `OpenAI-Organization` and `OpenAI-Project` headers, and the Stripe service strips `Stripe-Context` in addition to `Stripe-Account`. A caller can no longer pick the organization, project or account the operator's key acts on. Headers set with `ServiceBuilder::header` are still sent.
