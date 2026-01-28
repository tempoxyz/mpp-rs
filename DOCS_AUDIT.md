# mpay-rs Documentation Audit Report

**Date:** January 28, 2026  
**Auditor:** AI Documentation Review  
**Repository:** /Users/brendanryan/tempo/mpay-rs

## Summary

Overall documentation quality is **good**. The README is comprehensive, doc comments are well-written, and examples are practical. However, there are several inconsistencies between documented API and actual implementation, outdated example code patterns, and a few missing documentation areas.

---

## Critical Issues

### 1. README API Examples Don't Match Implementation

**Location:** README.md lines 33-41, 47-55, 59-64

**Issue:** The README shows a simplified API that doesn't match the actual implementation:

```rust
// README shows:
let challenge = Challenge::from_www_authenticate(header)?;
let credential = Credential::from_authorization(&header)?;
let receipt = Receipt::from_payment_receipt(header)?;

// Actual API (in protocol::core):
let challenge = parse_www_authenticate(header)?;  // standalone function
let credential = parse_authorization(&header)?;    // standalone function
let receipt = parse_receipt(header)?;              // standalone function
```

The `Challenge`, `Credential`, and `Receipt` modules re-export types but NOT the method-style APIs shown in the README.

**Recommendation:** Update README to show the correct module-qualified API:
```rust
use mpay::Challenge::parse_www_authenticate;
let challenge = parse_www_authenticate(header)?;
// OR
use mpay::protocol::core::parse_www_authenticate;
```

### 2. Incorrect Intent Import Path in README

**Location:** README.md line 127

**Issue:**
```rust
// README shows:
use mpay::Intent::ChargeRequest;

// Should be:
use mpay::Intent;
let request = Intent::ChargeRequest { ... };
// OR
use mpay::protocol::intents::ChargeRequest;
```

### 3. Server Example Shows Outdated TempoChargeMethod API

**Location:** README.md lines 143-155

**Issue:** The README shows:
```rust
let provider = ProviderBuilder::new()
    .connect_http("https://rpc.moderato.tempo.xyz".parse()?);
let method = TempoChargeMethod::new(provider);
```

But the actual implementation uses `tempo_provider()` helper:
```rust
use mpay::server::{tempo_provider, TempoChargeMethod};
let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
let method = TempoChargeMethod::new(provider);
```

---

## Moderate Issues

### 4. Example Files Have Outdated Struct Syntax

**Location:** examples/axum-server.md, examples/tower-middleware.md, examples/hyper-low-level.md

**Issue:** Examples use struct initialization syntax that doesn't match the actual `PaymentChallenge` fields:

```rust
// Examples show 'digest' field:
Challenge::PaymentChallenge {
    // ...
    digest: None,  // This field doesn't exist!
    expires: None,
    description: None,
}

// Actual struct only has:
pub struct PaymentChallenge {
    pub id: String,
    pub realm: String,
    pub method: MethodName,
    pub intent: IntentName,
    pub request: Base64UrlJson,
    pub expires: Option<String>,
    pub description: Option<String>,
}
```

**Files affected:**
- examples/tower-middleware.md (lines 177-186)
- examples/hyper-low-level.md (lines 102-116)

### 5. Custom Provider Example Has Wrong Payload Constructor

**Location:** examples/reqwest-client.md lines 157-162

**Issue:**
```rust
// Example shows:
Ok(PaymentCredential::new(
    challenge.to_echo(),
    PaymentPayload::hash("0x..."),
))

// But PaymentPayload::hash takes impl Into<String>, not &str literal:
PaymentPayload::hash("0x...")  // Correct but shows a static string
```

This is technically correct but misleading—should show dynamic usage.

### 6. fetch Example README Uses Testnet RPC Default

**Location:** examples/fetch/README.md line 33

**Issue:** Default RPC URL is `https://rpc.testnet.tempo.xyz/` but README shows moderato:
```bash
# README shows moderato but code defaults to testnet
--rpc-url https://rpc.testnet.tempo.xyz/
```

Should be consistent.

### 7. Missing `supports()` Method in Trait Documentation

**Location:** README.md lines 163-170

**Issue:** The client example shows:
```rust
assert!(provider.supports("tempo", "charge"));
```

But this method exists on `PaymentProvider` trait—documentation should clarify this is a trait method, not specific to `TempoProvider`.

---

## Minor Issues

### 8. Feature Flag Documentation Incomplete

**Location:** README.md Feature Flags table

**Issue:** The `utils` feature is defined in Cargo.toml but not documented in README:
```toml
# Cargo.toml has:
utils = ["hex", "rand"]
```

### 9. Doc Comments Reference Undocumented Helper Functions

**Location:** src/server/mod.rs

**Issue:** `tempo_provider()` is exported and used in examples but lacks comprehensive documentation about what it does differently from manual `ProviderBuilder` setup (it uses `TempoNetwork`).

### 10. Inconsistent RPC URL Examples

**Location:** Multiple files

**Issue:** Different RPC URLs used across documentation:
- `https://rpc.moderato.tempo.xyz` (README, some examples)
- `https://rpc.testnet.tempo.xyz/` (fetch example default)
- `https://rpc.example.com` (test files)

Should standardize on moderato for production examples.

### 11. Missing Error Handling Documentation

**Location:** README.md

**Issue:** No documentation on the `MppError` type and its variants. Users need to understand what errors can occur during:
- Challenge parsing
- Credential creation
- Payment verification

---

## Documentation Completeness

### Well Documented ✅
- Core protocol types (PaymentChallenge, PaymentCredential, Receipt)
- ChargeMethod trait and implementation pattern
- PaymentProvider trait for client-side
- HTTP extension trait (PaymentExt/Fetch)
- MultiProvider for multiple payment methods
- Base64UrlJson encoding/decoding

### Missing Documentation ❌
1. **Error types and handling** - `MppError` variants need docs
2. **TempoMethodDetails** - Method details JSON schema not documented
3. **EVM utilities** - `evm` module helpers not in README
4. **Wire format interoperability** - TypeScript SDK compatibility notes are in code but not in user docs
5. **Expiration handling** - How expires fields work across challenge/request

### Outdated Documentation ⚠️
1. Several example markdown files use old API patterns
2. README struct examples don't match actual field names
3. Some examples use deprecated patterns (struct literals vs. helper functions)

---

## Recommendations

### High Priority

1. **Update README.md** to reflect actual API:
   - Fix `Challenge::from_www_authenticate` → `Challenge::parse_www_authenticate`
   - Fix `Credential::from_authorization` → `Credential::parse_authorization`
   - Fix `Receipt::from_payment_receipt` → `Receipt::parse_receipt`
   - Update server example to use `tempo_provider()` helper

2. **Fix example markdown files**:
   - Remove `digest` field from PaymentChallenge examples
   - Update to use helper functions where available

3. **Add Error Documentation**:
   - Document `MppError` variants in README
   - Add troubleshooting section

### Medium Priority

4. **Standardize RPC URLs** across all documentation to use moderato
5. **Document `utils` feature** in README feature table
6. **Add wire format section** explaining TypeScript SDK interop

### Low Priority

7. **Add architecture diagram** using Mermaid
8. **Add changelog** tracking API changes
9. **Cross-reference IETF spec** more explicitly

---

## Code Quality Notes

The actual source code documentation (doc comments) is excellent:
- Clear module-level documentation
- Good examples in doc tests
- Proper use of `#[doc]` attributes
- Feature flag annotations on conditional code

The disconnect is primarily between the README/example files and the actual implementation, suggesting the API evolved after initial documentation was written.

---

## Appendix: Files Reviewed

| File | Status |
|------|--------|
| README.md | ⚠️ Needs updates |
| AGENTS.md | ✅ Good |
| src/lib.rs | ✅ Good |
| src/protocol/core/mod.rs | ✅ Excellent |
| src/protocol/core/challenge.rs | ✅ Excellent |
| src/protocol/core/types.rs | ✅ Excellent |
| src/protocol/intents/charge.rs | ✅ Good |
| src/protocol/traits/charge.rs | ✅ Good |
| src/client/mod.rs | ✅ Good |
| src/server/mod.rs | ✅ Good |
| src/http/mod.rs | ✅ Good |
| src/http/provider.rs | ✅ Good |
| src/http/ext.rs | ✅ Good |
| examples/README.md | ✅ Good |
| examples/fetch/README.md | ⚠️ RPC URL mismatch |
| examples/axum-server.md | ⚠️ Outdated structs |
| examples/reqwest-client.md | ✅ Mostly good |
| examples/custom-methods.md | ⚠️ Minor issues |
| examples/tower-middleware.md | ⚠️ Outdated structs |
| examples/hyper-low-level.md | ⚠️ Outdated structs |
