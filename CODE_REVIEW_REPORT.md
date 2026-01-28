# mpay-rs Code Review Report

**Date:** January 28, 2026  
**Scope:** Comprehensive code review of mpay-rs SDK  
**Effort Estimate:** ~1-3 hours for critical fixes, ~1-2 days for full remediation

---

## Executive Summary

The mpay-rs SDK is generally well-structured with clean separation of concerns between protocol core, intents, methods, and HTTP layers. However, there are several **high-priority security issues** that should be addressed:

1. **MethodName/IntentName normalization bypassed by serde** - Deserialization skips validation
2. **Unbounded header/request sizes** - Memory/CPU DoS potential
3. **Negative timestamp cast bug** - Can disable expiration checks
4. **Tempo receipt log parsing** - Can false-positive on malformed data

---

## Critical Issues (P0)

### 1. MethodName Deserialization Bypasses Validation

**Files:** `src/protocol/core/types.rs` (lines 31-56)

**Issue:** `MethodName` and `IntentName` derive `Deserialize` with `#[serde(transparent)]`, but the `new()` constructor that performs lowercase normalization is never called during deserialization.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]  // Deserialize bypasses new()
#[serde(transparent)]
pub struct MethodName(String);

impl MethodName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())  // This is never called on deserialize
    }
}
```

**Impact:** 
- Deserialized challenges/credentials can have uppercase or invalid method names
- Breaks protocol invariants (IETF spec: `method-name = 1*LOWERALPHA`)
- Could cause method selection bugs

**Fix:** Implement custom `Deserialize`:

```rust
impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let normalized = s.to_ascii_lowercase();
        if !normalized.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(serde::de::Error::custom("invalid method name"));
        }
        Ok(Self(normalized))
    }
}
```

---

### 2. Unbounded Header/Request Size - DoS Vector

**File:** `src/protocol/core/headers.rs`

**Issue:** `MAX_TOKEN_LEN` (16KB) is applied to Authorization/Receipt parsing, but NOT to:
- `WWW-Authenticate` header overall
- The `request=` parameter specifically

```rust
// Line 179-186: No size check before decoding
let request_b64 = params
    .get("request")
    .ok_or_else(|| MppError::InvalidChallenge("Missing 'request' field".to_string()))?
    .clone();

let _ = base64url_decode(&request_b64)?;  // Unbounded decode!
```

**Impact:** Attacker-controlled 402 responses can cause memory exhaustion via huge headers.

**Fix:** Add size limits before processing:

```rust
const MAX_HEADER_LEN: usize = 64 * 1024;  // 64KB for full header

pub fn parse_www_authenticate(header: &str) -> Result<PaymentChallenge> {
    if header.len() > MAX_HEADER_LEN {
        return Err(MppError::InvalidChallenge("Header exceeds maximum length".into()));
    }
    // ... existing code ...
    
    if request_b64.len() > MAX_TOKEN_LEN {
        return Err(MppError::InvalidChallenge("Request field exceeds maximum length".into()));
    }
    // ... rest of function
}
```

---

### 3. Negative Timestamp Cast Bug

**File:** `src/protocol/methods/tempo/mod.rs` (lines 222-228)

**Issue:** `unix_timestamp()` returns `i64`, but casting to `u64` wraps negative values:

```rust
pub(crate) fn parse_iso8601_timestamp(s: &str) -> Option<u64> {
    OffsetDateTime::parse(s.trim(), &Iso8601::DEFAULT)
        .ok()
        .map(|dt| dt.unix_timestamp() as u64)  // BUG: negative wraps to huge u64
}
```

**Impact:** Pre-1970 timestamps become huge future timestamps, disabling expiration checks.

**Fix:**

```rust
pub(crate) fn parse_iso8601_timestamp(s: &str) -> Option<u64> {
    OffsetDateTime::parse(s.trim(), &Iso8601::DEFAULT)
        .ok()
        .and_then(|dt| {
            let ts = dt.unix_timestamp();
            if ts >= 0 { Some(ts as u64) } else { None }
        })
}
```

---

### 4. Tempo Receipt Log Parsing False-Positive

**File:** `src/protocol/methods/tempo/method.rs` (lines 149-212)

**Issue:** Transfer event `data` parsing doesn't enforce exactly 32 bytes:

```rust
// Lines 200-205
if data.len() >= 66 {  // Should be == 66 for Transfer
    let amount = U256::from_str_radix(&data[2..], 16).unwrap_or(U256::ZERO);
    if amount >= expected_amount {
        return Ok(());
    }
}
```

**Impact:** Malformed logs with extra data could satisfy amount checks incorrectly.

**Fix:**

```rust
// Enforce exactly 32 bytes (64 hex chars + 0x prefix)
if data.len() == 66 {
    if let Ok(amount) = U256::from_str_radix(&data[2..], 16) {
        if amount >= expected_amount {
            return Ok(());
        }
    }
}
```

Also fix `unwrap_or_default()` on critical parsing (lines 184, 192):

```rust
// Instead of:
let topic0 = topics[0].parse::<B256>().unwrap_or_default();
// Use:
let topic0 = match topics[0].parse::<B256>() {
    Ok(t) => t,
    Err(_) => continue,  // Skip malformed logs
};
```

---

## High Priority Issues (P1)

### 5. Parameter Keys Should Be Case-Insensitive

**File:** `src/protocol/core/headers.rs` (lines 158-177)

**Issue:** HTTP auth-param keys are case-insensitive per RFC 7235, but parsing assumes lowercase.

**Fix:** Normalize keys in `parse_auth_params`:

```rust
params.insert(key.to_ascii_lowercase(), value);
```

---

### 6. Error Message Duplication

**Files:** 
- `src/protocol/core/types.rs` (line 255)
- `src/protocol/intents/charge.rs` (lines 69, 84)

**Issue:** Error messages have redundant prefixes:

```rust
// Displays as: "Invalid base64url: Invalid base64url: ..."
MppError::InvalidBase64Url(format!("Invalid base64url: {}", e))
```

**Fix:** Store only the detail:

```rust
MppError::InvalidBase64Url(e.to_string())
```

---

### 7. Misclassified Error Variants

**File:** `src/protocol/core/headers.rs`

**Issue:** `parse_authorization` and `parse_receipt` use `InvalidChallenge` for non-challenge errors:

```rust
// Line 349
.map_err(|e| MppError::InvalidChallenge(format!("Invalid credential JSON: {}", e)))?;
```

**Fix:** Use appropriate error variants:

```rust
.map_err(|e| MppError::CredentialFormat(format!("Invalid credential JSON: {}", e)))?;
```

---

### 8. Feature Flag Cycle

**File:** `Cargo.toml` (lines 18-30)

**Issue:** Circular dependency in features:
```toml
client = ["http"]
http = ["client", "reqwest"]
```

**Fix:** Make unidirectional:
```toml
client = []
http = ["client", "reqwest"]
```

---

## Medium Priority Issues (P2)

### 9. Documentation/Code Mismatch - Tempo Provider

**File:** `src/http/provider.rs`

**Issue:** Documentation claims support for:
- TempoTransactions (type 0x76)
- Fee sponsorship (`feePayer: true`)

But implementation uses standard ERC-20 transfers, not Tempo-specific transactions.

**Also:** Server verifier says "TIP-20 tokens exclusively (no native transfers)" but client supports native transfers.

**Fix:** Either implement the documented behavior or update documentation.

---

### 10. `now_iso8601()` Silent Fallback

**File:** `src/protocol/core/challenge.rs` (lines 320-327)

**Issue:** Returns "1970-01-01T00:00:00Z" on formatting failure, which could mask bugs.

**Fix:**
```rust
fn now_iso8601() -> String {
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .expect("time formatting should never fail")
}
```

---

### 11. Duplicate Scheme Parsing Logic

**File:** `src/protocol/core/headers.rs`

**Issue:** Both `parse_www_authenticate` and `parse_authorization` have similar case-insensitive scheme parsing.

**Fix:** Extract helper:
```rust
fn strip_payment_scheme(header: &str) -> Result<&str> {
    let header = header.trim_start();
    // ... unified implementation
}
```

---

### 12. `ResultExt::with_network` Confusing Behavior

**File:** `src/error.rs` (lines 243-250)

**Issue:** Wraps any error as `MppError::Signing` even for non-signing errors.

**Fix:** Either:
- Rename to `SigningResultExt` and restrict usage
- Only mutate existing `Signing` errors, pass through others

---

### 13. Inefficient `parse_auth_params` Implementation

**File:** `src/protocol/core/headers.rs` (lines 49-108)

**Issue:** Allocates `Vec<char>` unnecessarily; many intermediate `String` allocations.

**Fix:** Use byte-based scanning with `&str` slices.

---

### 14. `utils` Feature Misalignment

**File:** `Cargo.toml`

**Issue:** Feature `utils = ["hex", "rand"]` but `utils.rs` doesn't require these deps.

**Fix:** Remove feature or align with actual usage.

---

### 15. Dead Error Variants

**File:** `src/error.rs` (lines 135-143)

**Issue:** `HexDecode` and `Base64Decode` variants are cfg-gated behind `utils` but may be unused.

**Fix:** Audit usage; remove if dead code.

---

## Low Priority Issues (P3)

### 16. JSON Roundtripping in Receipt Verification

**File:** `src/protocol/methods/tempo/method.rs` (lines 156-163)

**Issue:** `serde_json::to_value(receipt)` then extracts logs - slower than typed access.

**Fix:** Use typed log access if available from `ReceiptResponse`.

---

### 17. Unnecessary Clones in Verify

**File:** `src/protocol/methods/tempo/method.rs` (lines 275-277)

**Issue:** Clones `credential` and `request` for the async block.

**Fix:** Consider boxed futures or `#[async_trait]` to avoid clones.

---

### 18. `unimplemented!()` in Test Mock

**File:** `src/http/middleware.rs` (line 122)

**Issue:** `MockProvider.pay` uses `unimplemented!()` which could leak into examples.

**Fix:** Return `Err(MppError::UnsupportedPaymentMethod(...))`.

---

## Recommendations Summary

### Immediate Actions (Do Now)
1. ✅ Implement custom `Deserialize` for `MethodName` and `IntentName`
2. ✅ Add size limits to `parse_www_authenticate` 
3. ✅ Fix negative timestamp cast in `parse_iso8601_timestamp`
4. ✅ Fix Tempo receipt log parsing to enforce exact sizes

### Short-Term (This Sprint)
5. Normalize auth-param keys to lowercase
6. Fix error message duplication
7. Use correct error variants for credential/receipt parsing
8. Fix feature flag cycle in Cargo.toml

### Medium-Term (Next Sprint)
9. Align Tempo provider docs with implementation
10. Extract common scheme parsing helper
11. Review and fix `ResultExt::with_network` behavior
12. Optimize `parse_auth_params`

### Consider for Future
- Add fuzz tests for header parsing
- Structured public/internal error separation
- Replace custom parser with tested HTTP auth-param library

---

## Testing Recommendations

Add tests for:
1. MethodName deserialization with uppercase/invalid chars
2. Very large WWW-Authenticate headers
3. Pre-1970 expiration timestamps
4. Malformed Transfer event logs with extra data
5. Mixed-case auth-param keys

---

## Appendix: Files Changed

| File | Priority | Issues |
|------|----------|--------|
| `src/protocol/core/types.rs` | P0 | #1, #6 |
| `src/protocol/core/headers.rs` | P0, P1 | #2, #5, #7, #11 |
| `src/protocol/methods/tempo/mod.rs` | P0 | #3 |
| `src/protocol/methods/tempo/method.rs` | P0, P3 | #4, #16, #17 |
| `src/http/provider.rs` | P2 | #9 |
| `src/protocol/core/challenge.rs` | P2 | #10 |
| `src/error.rs` | P2 | #12, #15 |
| `Cargo.toml` | P1 | #8, #14 |
| `src/http/middleware.rs` | P3 | #18 |
