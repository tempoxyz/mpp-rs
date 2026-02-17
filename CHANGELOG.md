# Changelog

## `mpp@0.3.0`

### Minor Changes

- Simplified server API with dollar amounts and smart defaults. Added `Mpp::create()` and `mpp.charge("1")` for one-line payment setup.
- Added default 5-minute expiration for challenges and `prepare_request` hook for request customization.
- Aligned Rust SDK with mppx TypeScript SDK for cross-language consistency.
- Removed failed receipt state — server now returns 402 for payment failures per IETF spec.
- Fixed tempo payment method to match TypeScript SDK behavior. Fixed 402 responses for failed receipts per spec.
- Updated `rand` dependency from 0.8 to 0.9. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))

### Patch Changes

- Mandated JCS (RFC 8785) for canonical JSON serialization of request parameters by replacing `serde_json::to_string` with `serde_json_canonicalizer::to_string` throughout the protocol layer. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated currency address from AlphaUSD to PathUSD across all examples, documentation, and tests. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Normalized error codes to kebab-case format per IETF spec update (§8.2). (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated documentation URL and optimized CI workflows. Added GitHub Pages documentation deployment, switched to cargo-hack for feature testing, and pinned release workflow to commit SHA. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))

