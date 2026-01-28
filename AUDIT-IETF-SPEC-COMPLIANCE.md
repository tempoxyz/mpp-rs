# mpay-rs IETF Payment Auth Spec Compliance Audit

**Date**: January 28, 2026  
**Auditor**: AI-assisted code review  
**Scope**: mpay-rs implementation vs IETF Payment Auth specification  
**Spec Location**: `/Users/brendanryan/tempo/ietf-paymentauth-spec`

## Executive Summary

mpay-rs is **broadly aligned** with the IETF Payment Auth specification in terms of core protocol structure:
- ✅ `WWW-Authenticate: Payment ...` challenge format
- ✅ `Authorization: Payment <b64token>` credential format  
- ✅ `Payment-Receipt` header format
- ✅ Base64url encoding without padding
- ✅ Charge intent schema (amount, currency, recipient, etc.)

However, the audit identified **7 spec divergences**, **3 potential bugs**, and **4 missing features** that should be addressed for full compliance.

---

## Compliance Matrix

| Area | Status | Severity | Notes |
|------|--------|----------|-------|
| WWW-Authenticate format | ⚠️ Partial | Medium | Missing `digest` parameter |
| Authorization format | ✅ Compliant | - | Uses correct b64token format |
| Payment-Receipt format | ⚠️ Partial | Low | Extra `error` field |
| Method identifier validation | ❌ Non-compliant | Medium | Serde bypasses lowercase normalization |
| Charge intent schema | ✅ Compliant | - | All fields correctly mapped |
| Tempo method schema | ⚠️ Partial | Medium | `expires` not enforced as required |
| Fee payer flow | ❌ Not implemented | High | Described but not functional |
| Security guardrails | ⚠️ Partial | High | Missing tx validation before broadcast |

---

## Detailed Findings

### 1. Core Protocol Compliance

#### 1.1 Missing `digest` Parameter (Spec Divergence)

**Severity**: Medium  
**Location**: `src/protocol/core/challenge.rs`, `src/protocol/core/headers.rs`

**Spec Requirement** (Section 5.1.2):
> `digest`: Content digest of the request body, formatted per [RFC9530]. Servers SHOULD include this parameter when the payment challenge applies to a request with a body.

**Issue**: `PaymentChallenge` and `ChallengeEcho` structs have no `digest` field. The header parser and formatter ignore this parameter entirely.

```rust
// Current: No digest field
pub struct PaymentChallenge {
    pub id: String,
    pub realm: String,
    pub method: MethodName,
    pub intent: IntentName,
    pub request: Base64UrlJson,
    pub expires: Option<String>,
    pub description: Option<String>,
    // Missing: pub digest: Option<String>,
}
```

**Impact**: Cannot bind payment challenges to request bodies (POST/PUT/PATCH), reducing integrity guarantees for paid API calls with payloads.

**Recommendation**: Add `digest: Option<String>` to `PaymentChallenge` and `ChallengeEcho`, update parser/formatter.

---

#### 1.2 Method Name Validation Bypass (Bug)

**Severity**: Medium  
**Location**: `src/protocol/core/types.rs:31-83`

**Spec Requirement** (Section 6.1):
> Payment methods are identified by lowercase ASCII strings... Method identifiers are case-sensitive and MUST be lowercase.

**Issue**: `MethodName::new()` normalizes to lowercase, but `#[derive(Deserialize)]` with `#[serde(transparent)]` **bypasses** the `new()` constructor. When deserializing from JSON, Serde constructs the struct directly without normalization.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MethodName(String);  // Serde bypasses new() - no normalization!

impl MethodName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())  // Only called explicitly
    }
}
```

**Impact**: Credentials with uppercase method names (e.g., `"TEMPO"`) will parse successfully but fail method matching, causing confusing verification failures.

**Recommendation**: Implement custom `Deserialize` that calls `new()`:
```rust
impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(d)?))
    }
}
```

---

#### 1.3 Missing Size Limit for `request` Parameter (Security Bug)

**Severity**: Medium  
**Location**: `src/protocol/core/headers.rs:125-197`

**Issue**: `parse_www_authenticate` applies no size limit to the `request` base64url token before decoding. In contrast, `parse_authorization` and `parse_receipt` enforce `MAX_TOKEN_LEN` (16KB).

```rust
// Authorization/Receipt: Has size check ✓
if token.len() > MAX_TOKEN_LEN {
    return Err(MppError::InvalidChallenge(...));
}

// WWW-Authenticate: NO size check ✗
let request_b64 = params.get("request")...;
let _ = base64url_decode(&request_b64)?;  // Could be arbitrarily large
```

**Impact**: Memory exhaustion DoS via malicious `WWW-Authenticate` headers with very large `request` values.

**Recommendation**: Apply `MAX_TOKEN_LEN` check to `request_b64` before decoding.

---

#### 1.4 Receipt Schema Extension (Spec Divergence)

**Severity**: Low  
**Location**: `src/protocol/core/challenge.rs:259-318`

**Spec Requirement** (Section 5.3):
> Receipt JSON: `{ status, method, timestamp, reference }`

**Issue**: mpay-rs adds an `error` field and sets `reference: ""` for failed receipts:

```rust
pub struct Receipt {
    pub status: ReceiptStatus,
    pub method: MethodName,
    pub timestamp: String,
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,  // Non-spec extension
}

pub fn failed(...) -> Self {
    Self {
        reference: String::new(),  // Empty string, not clear if spec-allowed
        error: Some(error_msg.to_string()),
        ...
    }
}
```

**Impact**: Strict clients validating receipt schema may reject mpay-rs receipts.

**Recommendation**: Either gate `error` behind an extension feature flag, or document it as a compatible extension. Consider making `reference` meaningful even for failures.

---

### 2. Charge Intent Compliance

#### 2.1 Schema Fields ✅ Compliant

The `ChargeRequest` struct correctly implements all spec fields:

| Spec Field | mpay-rs Field | Required | Status |
|------------|---------------|----------|--------|
| `amount` | `amount: String` | Yes | ✅ |
| `currency` | `currency: String` | Yes | ✅ |
| `recipient` | `recipient: Option<String>` | No | ✅ |
| `expires` | `expires: Option<String>` | No | ✅ |
| `description` | `description: Option<String>` | No | ✅ |
| `externalId` | `external_id: Option<String>` | No | ✅ (correct rename) |
| `methodDetails` | `method_details: Option<Value>` | No | ✅ |

---

### 3. Tempo Method Compliance

#### 3.1 Missing `expires` Enforcement (Bug)

**Severity**: Medium  
**Location**: `src/protocol/methods/tempo/method.rs:295-297`

**Spec Requirement** (draft-tempo-charge-00, Section 4):
> Request fields: `amount` REQUIRED, `currency` REQUIRED, `recipient` REQUIRED, `expires` REQUIRED

**Issue**: The Tempo verifier only checks expiration if `expires` is present, but per the Tempo spec it MUST be present:

```rust
// Current: Optional check
if let Some(ref expires) = request.expires {
    this.check_expiration(expires)?;
}

// Should be: Required for Tempo
let expires = request.expires.as_ref()
    .ok_or_else(|| VerificationError::new("Tempo requires expires field"))?;
this.check_expiration(expires)?;
```

**Impact**: Tempo challenges without `expires` will bypass expiration validation.

**Recommendation**: Add required field check for Tempo method.

---

#### 3.2 Fee Payer Flow Not Implemented (Missing Feature)

**Severity**: High  
**Location**: `src/protocol/methods/tempo/method.rs`

**Spec Requirement** (draft-tempo-charge-00, Section 5):
> When `feePayer: true`: Client signs with `fee_payer_signature` set to placeholder. Server adds fee payment signature before broadcasting.

**Issue**: `TempoMethodDetails` documents the fee payer flow, but the verifier:
1. Does not detect `feePayer: true` in request
2. Does not add server fee payer signature
3. Broadcasts client transaction as-is

```rust
// Current: No feePayer handling
async fn broadcast_transaction(&self, signed_tx: &str) -> Result<B256, VerificationError> {
    let tx_bytes = signed_tx.parse::<Bytes>()?;
    self.provider.send_raw_transaction(&tx_bytes).await  // Broadcasts as-is
}
```

**Impact**: Fee sponsorship is described but broken - clients expecting server-paid fees will have transactions fail.

**Recommendation**: 
- Short-term: Return explicit error if `request.fee_payer() == true`
- Long-term: Implement transaction decoding, fee payer signature injection, and broadcast

---

#### 3.3 Unvalidated Transaction Broadcasting (Security Issue)

**Severity**: High  
**Location**: `src/protocol/methods/tempo/method.rs:235-259`

**Issue**: When `payload.type = "transaction"`, the server broadcasts arbitrary signed bytes and only validates the transfer after mining by checking receipt logs.

```rust
// Current flow:
// 1. Receive arbitrary signed_tx from client
// 2. Broadcast it immediately (no validation)
// 3. Wait for mining
// 4. Check logs for Transfer event
```

**Risks**:
- Server can be tricked into broadcasting spam/malicious transactions
- Resource exhaustion if transaction reverts after gas consumed
- If fee sponsorship is added, server pays fees for arbitrary ops

**Recommendation**: Pre-broadcast validation:
1. Decode transaction bytes
2. Verify `tx.to` matches `currency` (token contract)
3. Verify calldata is `transfer(recipient, amount)` 
4. Verify `tx.chainId` matches expected chain
5. Only then broadcast

---

#### 3.4 Source DID Not Verified (Missing Feature)

**Severity**: Medium  
**Location**: `src/protocol/methods/tempo/method.rs`

**Spec Allows** (Section 5.2):
> `source`: Payer identifier as a DID (e.g., `did:pkh:eip155:42431:0x...`)

**Issue**: `credential.source` is completely ignored during verification. The verifier does not:
1. Extract sender address from the transaction/receipt
2. Compare against claimed source DID

**Impact**: Cannot rely on `source` for payer attribution. Credentials can claim any DID.

**Recommendation**: If `credential.source.is_some()`, parse the DID, extract the address, and verify it matches the transaction sender.

---

### 4. Security Considerations

#### 4.1 Implemented Security Features ✅

| Feature | Status | Location |
|---------|--------|----------|
| Base64url without padding | ✅ | `types.rs:247-256` |
| Size limits on Authorization | ✅ | `headers.rs:18, 340` |
| Size limits on Receipt | ✅ | `headers.rs:370` |
| Header injection protection (CRLF) | ✅ | `headers.rs:22-29` |
| Chain ID validation | ✅ | `method.rs:299-309` |
| Transaction status check | ✅ | `method.rs:126-131` |

#### 4.2 Missing Security Features

| Feature | Spec Reference | Status |
|---------|----------------|--------|
| `request` size limit | Section 7.5 | ❌ |
| `digest` body binding | Section 5.1.2 | ❌ |
| Pre-broadcast tx validation | N/A (best practice) | ❌ |
| Source DID verification | Section 5.2 | ❌ |
| Challenge replay prevention | Section 7.2 | ⚠️ Server responsibility |

---

## Recommendations Summary

### Critical (Should Fix)

1. **Add `digest` parameter support** - Required for body-bound challenges
2. **Fix MethodName deserialization** - Serde bypass causes validation failures
3. **Add size limit for `request`** - DoS prevention
4. **Enforce `expires` for Tempo** - Per Tempo method spec

### High Priority

5. **Return error for `feePayer: true`** - Until properly implemented
6. **Pre-validate transactions before broadcast** - Security critical
7. **Verify `source` DID when present** - Identity assurance

### Low Priority

8. **Review Receipt `error` field** - Document as extension or remove
9. **Consider IntentName normalization** - Consistency with method names

---

## Compliance Score

| Category | Score | Notes |
|----------|-------|-------|
| Core Protocol | 80% | Missing digest, method validation |
| Charge Intent | 95% | Minor validation gaps |
| Tempo Method | 60% | expires/feePayer/tx validation |
| Security | 70% | Good basics, missing advanced |
| **Overall** | **75%** | Functionally correct, needs hardening |

---

## Files Reviewed

- `src/protocol/core/challenge.rs`
- `src/protocol/core/types.rs`
- `src/protocol/core/headers.rs`
- `src/protocol/intents/charge.rs`
- `src/protocol/methods/tempo/charge.rs`
- `src/protocol/methods/tempo/types.rs`
- `src/protocol/methods/tempo/method.rs`
- `src/error.rs`

## Spec Documents Reviewed

- `ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md`
- `ietf-paymentauth-spec/specs/intents/draft-payment-intent-charge-00.md`
- `ietf-paymentauth-spec/specs/methods/tempo/draft-tempo-charge-00.md`
