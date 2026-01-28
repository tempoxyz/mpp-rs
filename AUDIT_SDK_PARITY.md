# mpay SDK Parity Audit

Comparison between **mpay-rs** (Rust) and **mpay** (TypeScript) SDKs.

---

## Executive Summary

| Feature | TypeScript | Rust | Gap |
|---------|------------|------|-----|
| Core Protocol | ✅ | ✅ | - |
| Intents: charge | ✅ | ✅ | - |
| Intents: authorize | ✅ | ❌ | Missing |
| Intents: subscription | ✅ | ❌ | Missing |
| Client fetch wrapper | ✅ | ✅ | - |
| Client middleware | ✅ | ✅ | - |
| Server verification | ✅ | ✅ | - |
| Tempo method | ✅ | ✅ | - |
| Fee payer support | ✅ | ✅ (partial) | Server-side only in RS |
| MCP transport | ✅ | ❌ | Missing |
| Custom transports | ✅ | ❌ | Missing |
| RFC 9457 errors | ✅ | ❌ | Missing |
| HMAC-bound challenges | ✅ | ❌ | Missing |
| Multi-provider | ❌ | ✅ | RS has extra |

---

## 1. Functionality Differences

### 1.1 Intents Supported

**TypeScript (mpay):**
- `charge` — One-time immediate payments
- `authorize` — Pre-authorization with spending limits
- `subscription` — Recurring periodic payments

**Rust (mpay-rs):**
- `charge` — One-time immediate payments

**Gap:** Rust SDK lacks `authorize` and `subscription` intents.

---

### 1.2 Transport Layer

**TypeScript:**
- HTTP transport (402 status → WWW-Authenticate)
- MCP transport (error code -32042 → challenges array)
- Custom transports via `Transport.from()`

**Rust:**
- HTTP only via reqwest

**Gap:** Rust SDK lacks MCP transport and pluggable transport abstraction.

---

### 1.3 Server-Side Features

**TypeScript:**
- HMAC-bound challenge IDs (stateless verification)
- RFC 9457 Problem Details error responses
- Node.js HTTP listener adapter (`Mpay.toNodeListener`)
- Intent-specific handlers with typed request transformation
- Per-request context schema

**Rust:**
- `ChargeMethod` trait for verification
- `TempoChargeMethod` implementation
- Basic verification errors

**Gap:** Rust lacks HMAC-bound challenges, RFC 9457 errors, and the high-level `Mpay.create()` server abstraction.

---

### 1.4 Client-Side Features

**TypeScript:**
- `Fetch.from()` — returns wrapped fetch function
- `Fetch.polyfill()` — replaces global fetch
- `Fetch.restore()` — restores original fetch
- `Mpay.create()` — client with explicit `createCredential()`
- Per-request context for dynamic accounts

**Rust:**
- `PaymentExt` trait with `.send_with_payment()`
- `PaymentMiddleware` for reqwest-middleware
- `MultiProvider` for multiple payment methods
- `TempoProvider` implementation

**Gap:** Rust lacks `polyfill/restore` pattern and transport-agnostic client.

---

### 1.5 Error Handling

**TypeScript (RFC 9457 compliant):**
```typescript
PaymentRequiredError        // No credential provided
MalformedCredentialError    // Invalid base64/JSON
InvalidChallengeError       // Challenge ID invalid/expired
VerificationFailedError     // Proof verification failed
PaymentExpiredError         // Payment expired
InvalidPayloadError         // Credential payload invalid
```

**Rust (thiserror-based):**
```rust
MppError::InvalidChallenge      // Challenge parse error
MppError::ChallengeExpired      // Expired challenge
MppError::InvalidCredential     // Invalid credential
VerificationError              // Server-side errors
```

**Gap:** Rust errors don't implement RFC 9457 Problem Details (`type`, `title`, `detail` URIs).

---

### 1.6 Tempo Method Details

**TypeScript Client:**
- Signs Tempo transactions (type 0x76)
- Supports `feePayer: true` in methodDetails
- Uses viem for transaction building/signing

**Rust Client:**
- Signs Tempo transactions
- Handles ERC-20 transfers
- Uses alloy for transaction building/signing
- **Missing:** Pre-signed transaction payload type

**TypeScript Server:**
- Verifies `hash` payloads (tx already submitted)
- Verifies `transaction` payloads (pre-signed, server submits)
- Fee payer co-signing support

**Rust Server:**
- Verifies `hash` payloads only
- **Missing:** `transaction` payload verification

---

## 2. Interface Design Differences

### 2.1 Namespace Pattern

**TypeScript:** PascalCase namespace exports
```typescript
import { Challenge, Credential, Receipt, Intent } from 'mpay'
Challenge.fromResponse(res)
Credential.serialize(cred)
```

**Rust:** PascalCase modules (matching TS pattern)
```rust
use mpay::{Challenge, Credential, Receipt, Intent};
Challenge::parse_www_authenticate(header)?;
Credential::format_authorization(&cred)?;
```

**Design:** Both use PascalCase namespaces — good parity.

---

### 2.2 Entry Points

**TypeScript:**
```
mpay               — Core primitives
mpay/client        — Client SDK
mpay/server        — Server SDK
mpay/tempo         — Tempo intents
mpay/mcp-sdk/client — MCP client wrapper
mpay/mcp-sdk/server — MCP server transport
```

**Rust:**
```
mpay                     — Core + re-exports
mpay::client             — PaymentProvider, Fetch, TempoProvider
mpay::server             — ChargeMethod, TempoChargeMethod
mpay::protocol           — Core types
mpay::tempo              — Tempo-specific types
```

**Gap:** Rust lacks `mcp-sdk` entry points entirely.

---

### 2.3 Method Definition Pattern

**TypeScript:** Composable method builders
```typescript
const method = Method.toClient(Methods.tempo, {
  context: z.object({ account: z.custom<Account>() }),
  async createCredential({ challenge, context }) { ... }
})
```

**Rust:** Trait-based
```rust
impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool { ... }
    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential> { ... }
}
```

**Design difference:** TypeScript uses runtime composition; Rust uses compile-time traits.

---

### 2.4 Challenge Creation

**TypeScript:** HMAC-bound IDs (stateless)
```typescript
const challenge = Challenge.fromIntent(intent, {
  realm: 'api.example.com',
  request: { amount: '1000', ... },
  secretKey: 'my-secret',  // Computes HMAC ID
})

// Server verifies without storing:
Challenge.verify(credential.challenge, { secretKey })
```

**Rust:** No HMAC binding
```rust
// Must use external ID generation or storage
let challenge = PaymentChallenge::new(id, realm, method, intent, request);
```

**Gap:** Rust requires external challenge ID management.

---

## 3. Object Graphs (ASCII Diagrams)

### TypeScript SDK Architecture

```
                              ┌─────────────────────────────────────────┐
                              │              mpay (core)                │
                              ├─────────────────────────────────────────┤
                              │  Challenge   Credential   Receipt       │
                              │  Intent      Method       MethodIntent  │
                              │  Errors      Mcp         z (zod)        │
                              └──────────────────┬──────────────────────┘
                                                 │
                     ┌───────────────────────────┼───────────────────────────┐
                     │                           │                           │
                     ▼                           ▼                           ▼
          ┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
          │   mpay/client    │       │   mpay/server    │       │   mpay/tempo     │
          ├──────────────────┤       ├──────────────────┤       ├──────────────────┤
          │  Mpay.create()   │       │  Mpay.create()   │       │  Intents.charge  │
          │  Fetch.from()    │       │  Request.*       │       │                  │
          │  Fetch.polyfill()│       │  Response.*      │       │                  │
          │  Transport.http()│       │  Transport.http()│       │                  │
          │  Transport.mcp() │       │  toNodeListener()│       │                  │
          │  tempo(params)   │       │  tempo(params)   │       │                  │
          └────────┬─────────┘       └────────┬─────────┘       └──────────────────┘
                   │                          │
                   ▼                          ▼
          ┌──────────────────┐       ┌──────────────────┐
          │ tempo/client/    │       │ tempo/server/    │
          │   Method.ts      │       │   Method.ts      │
          ├──────────────────┤       ├──────────────────┤
          │ createCredential │       │ verify()         │
          │  • sign tx       │       │  • hash payload  │
          │  • via viem      │       │  • tx payload    │
          │                  │       │  • feePayer      │
          └──────────────────┘       └──────────────────┘

          ┌──────────────────────────────────────────────┐
          │              mpay/mcp-sdk                    │
          ├─────────────────────┬────────────────────────┤
          │   mcp-sdk/client    │    mcp-sdk/server      │
          │  McpClient.wrap()   │    Transport.*         │
          │  isPaymentRequired()│                        │
          └─────────────────────┴────────────────────────┘
```

### Rust SDK Architecture

```
                              ┌─────────────────────────────────────────┐
                              │              mpay (lib.rs)              │
                              ├─────────────────────────────────────────┤
                              │  Challenge   Credential   Receipt       │
                              │  Intent      Schema       error         │
                              │  Signer (re-export)                     │
                              └──────────────────┬──────────────────────┘
                                                 │
                     ┌───────────────────────────┼───────────────────────────┐
                     │                           │                           │
                     ▼                           ▼                           ▼
          ┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
          │   client/mod.rs  │       │   server/mod.rs  │       │   tempo/mod.rs   │
          │  (feature:client)│       │  (feature:server)│       │  (feature:tempo) │
          ├──────────────────┤       ├──────────────────┤       ├──────────────────┤
          │  PaymentProvider │       │  ChargeMethod    │       │  TempoCharge-    │
          │  PaymentExt      │       │  VerificationErr │       │    Ext           │
          │  (Fetch alias)   │       │  ErrorCode       │       │  TempoMethod-    │
          │  PaymentMiddle-  │       │  TempoCharge-    │       │    Details       │
          │    ware          │       │    Method        │       │  CHAIN_ID        │
          │  TempoProvider   │       │  tempo_provider()│       │                  │
          │  MultiProvider   │       │                  │       │                  │
          └────────┬─────────┘       └────────┬─────────┘       └──────────────────┘
                   │                          │
                   │                          │
                   ▼                          ▼
          ┌──────────────────────────────────────────────────────┐
          │                   http/mod.rs                        │
          │                  (feature:http)                      │
          ├──────────────────────────────────────────────────────┤
          │  ext.rs      │  provider.rs   │  middleware.rs       │
          │  PaymentExt  │  PaymentProv.  │  PaymentMiddleware   │
          │  .send_with_ │  TempoProvider │  (reqwest-middleware)│
          │   payment()  │  MultiProvider │                      │
          └──────────────┴────────────────┴──────────────────────┘

          ┌──────────────────────────────────────────────────────┐
          │               protocol/mod.rs                        │
          ├───────────────┬────────────────┬─────────────────────┤
          │   core/       │   intents/     │   traits/           │
          │  Challenge    │  ChargeRequest │  ChargeMethod       │
          │  Credential   │                │  VerificationError  │
          │  Receipt      │                │  ErrorCode          │
          │  headers.rs   │                │                     │
          └───────────────┴────────────────┴─────────────────────┘
```

### Side-by-Side Comparison

```
┌─────────────────────────────────────┐  ┌─────────────────────────────────────┐
│        TypeScript (mpay)            │  │          Rust (mpay-rs)             │
├─────────────────────────────────────┤  ├─────────────────────────────────────┤
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Entry Points            │    │  │  │     Entry Points            │    │
│  │  • mpay (core)              │    │  │  │  • mpay (core + all)        │    │
│  │  • mpay/client              │    │  │  │  • mpay::client             │    │
│  │  • mpay/server              │    │  │  │  • mpay::server             │    │
│  │  • mpay/tempo               │    │  │  │  • mpay::tempo              │    │
│  │  • mpay/mcp-sdk/client  ◀───┼────┼──┼──┤  (missing)                  │    │
│  │  • mpay/mcp-sdk/server  ◀───┼────┼──┼──┤  (missing)                  │    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Core Types              │    │  │  │     Core Types              │    │
│  │  • Challenge ✓              │    │  │  │  • PaymentChallenge ✓       │    │
│  │  • Credential ✓             │    │  │  │  • PaymentCredential ✓      │    │
│  │  • Receipt ✓                │    │  │  │  • Receipt ✓                │    │
│  │  • ChallengeEcho ✓          │    │  │  │  • ChallengeEcho ✓          │    │
│  │  • PaymentPayload ✓         │    │  │  │  • PaymentPayload ✓         │    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Intents                 │    │  │  │     Intents                 │    │
│  │  • charge ✓                 │    │  │  │  • ChargeRequest ✓          │    │
│  │  • authorize ◀──────────────┼────┼──┼──┤  (missing)                  │    │
│  │  • subscription ◀───────────┼────┼──┼──┤  (missing)                  │    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Client Features         │    │  │  │     Client Features         │    │
│  │  • Fetch.from() ✓           │    │  │  │  • PaymentExt ✓             │    │
│  │  • Fetch.polyfill() ◀───────┼────┼──┼──┤  (missing)                  │    │
│  │  • Mpay.create() ✓          │    │  │  │  • PaymentMiddleware ✓      │    │
│  │  • Transport.http() ✓       │    │  │  │  (http only)                │    │
│  │  • Transport.mcp() ◀────────┼────┼──┼──┤  (missing)                  │    │
│  │  • per-request context ✓    │    │  │  │  (not supported)            │    │
│  │                             │    │  │  │  • MultiProvider ──────────▶│    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Server Features         │    │  │  │     Server Features         │    │
│  │  • Mpay.create() ✓          │    │  │  │  • ChargeMethod trait ✓     │    │
│  │  • HMAC challenges ◀────────┼────┼──┼──┤  (missing)                  │    │
│  │  • RFC 9457 errors ◀────────┼────┼──┼──┤  (missing)                  │    │
│  │  • toNodeListener() ✓       │    │  │  │  (no adapter)               │    │
│  │  • hash payload ✓           │    │  │  │  • hash payload ✓           │    │
│  │  • tx payload ✓             │    │  │  │  • tx payload ◀─────────────│    │
│  │  • feePayer co-sign ✓       │    │  │  │  (missing)                  │    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
│                                     │  │                                     │
│  ┌─────────────────────────────┐    │  │  ┌─────────────────────────────┐    │
│  │     Tempo Method            │    │  │  │     Tempo Method            │    │
│  │  Client:                    │    │  │  │  Client:                    │    │
│  │   • viem signing ✓          │    │  │  │   • alloy signing ✓         │    │
│  │   • dynamic account ✓       │    │  │  │   • fixed signer only       │    │
│  │  Server:                    │    │  │  │  Server:                    │    │
│  │   • Transfer logs ✓         │    │  │  │   • Transfer logs ✓         │    │
│  │   • TransferWithMemo ✓      │    │  │  │   • (missing memo)          │    │
│  │   • pre-signed tx ✓         │    │  │  │   • (hash only)             │    │
│  └─────────────────────────────┘    │  │  └─────────────────────────────┘    │
└─────────────────────────────────────┘  └─────────────────────────────────────┘
```

---

## 4. Recommendations for Parity

### Priority 1: Critical Gaps

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 1 | **Server: HMAC-bound challenge IDs** | Medium | Enables stateless verification |
| 2 | **Server: `transaction` payload verification** | Medium | Full Tempo flow support |
| 3 | **Server: Fee payer co-signing** | Medium | Required for sponsored txs |
| 4 | **RFC 9457 error types** | Low | Spec compliance |

### Priority 2: Feature Completeness

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 5 | **Intents: `authorize`** | Medium | Pre-auth use cases |
| 6 | **Intents: `subscription`** | Medium | Recurring payments |
| 7 | **MCP transport** | High | AI agent ecosystem |
| 8 | **TransferWithMemo verification** | Low | Idempotency support |

### Priority 3: API Ergonomics

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 9 | **High-level `Mpay::server()` builder** | Medium | Match TS DX |
| 10 | **Per-request context (client)** | Medium | Dynamic accounts |
| 11 | **Transport abstraction** | High | Pluggable protocols |
| 12 | **`polyfill` pattern** | Low | Global replacement |

---

### Suggested Implementation Order

```
Phase 1 (Core Parity):
  ├── 1. HMAC-bound challenge IDs
  ├── 4. RFC 9457 error types
  └── 8. TransferWithMemo verification

Phase 2 (Full Tempo):
  ├── 2. Transaction payload verification
  └── 3. Fee payer co-signing

Phase 3 (Extended Intents):
  ├── 5. Authorize intent
  └── 6. Subscription intent

Phase 4 (MCP Integration):
  ├── 7. MCP transport
  └── 11. Transport abstraction

Phase 5 (DX Polish):
  ├── 9. Mpay::server() builder
  ├── 10. Per-request context
  └── 12. Polyfill pattern
```

---

## Appendix: Feature Flags Comparison

### TypeScript (package.json exports)
```json
{
  ".": "core primitives",
  "./client": "client SDK",
  "./server": "server SDK",
  "./tempo": "tempo intents",
  "./mcp-sdk/client": "MCP client",
  "./mcp-sdk/server": "MCP server"
}
```

### Rust (Cargo.toml features)
```toml
[features]
default = ["tempo"]
client = ["http"]
server = []
evm = ["alloy", "..."]
tempo = ["evm", "tempo-alloy", "..."]
http = ["client", "reqwest"]
middleware = ["http", "reqwest-middleware", "..."]
```

**Note:** Rust uses additive feature flags; TypeScript uses separate entry points.

---

*Generated: 2025-01-28*
