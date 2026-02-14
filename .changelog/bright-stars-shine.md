---
mpp: minor
---

Simplified server API with dollar amounts and smart defaults. Added `Mpp::create()` and `mpp.charge("1")` for one-line payment setup.

Added default 5-minute expiration for challenges and `prepare_request` hook for request customization.

Aligned Rust SDK with mppx TypeScript SDK for cross-language consistency.

Removed failed receipt state — server now returns 402 for payment failures per IETF spec.

Fixed tempo payment method to match TypeScript SDK behavior. Fixed 402 responses for failed receipts per spec.

Updated `rand` dependency from 0.8 to 0.9.
