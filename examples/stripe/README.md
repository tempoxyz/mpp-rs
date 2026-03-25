# Stripe Example

A pay-per-fortune API using Stripe's Shared Payment Token (SPT) flow.

## What This Demonstrates

- Server-side payment protection with `Mpp::create_stripe()` and the Stripe method
- SPT proxy endpoint (secret key stays server-side)
- Headless client using a test card (`pm_card_visa`)
- Full 402 → challenge → credential → retry flow

## Prerequisites

- Rust 1.80+
- A Stripe test-mode secret key (`sk_test_...`)

## Running

**Start the server:**

```bash
export STRIPE_SECRET_KEY=sk_test_...
cargo run --bin stripe-server
```

The server starts at http://localhost:3000.

**Run the client** (in another terminal):

```bash
cargo run --bin stripe-client
# 🥠 A smooth long journey! Great expectations.
# Payment receipt: pi_3Q...
```

## Testing Manually

**Without payment** (returns 402):

```bash
curl -i http://localhost:3000/api/fortune
# HTTP/1.1 402 Payment Required
# WWW-Authenticate: Payment ...
```

## How It Works

```
Client                           Server                          Stripe
  │                                │                               │
  │  GET /api/fortune              │                               │
  ├──────────────────────────────> │                               │
  │                                │                               │
  │  402 + WWW-Authenticate        │                               │
  │<────────────────────────────── │                               │
  │                                │                               │
  │  POST /api/create-spt          │                               │
  ├──────────────────────────────> │  Create SPT (test helper)     │
  │                                ├─────────────────────────────> │
  │                    spt_...     │                               │
  │<────────────────────────────── │<───────────────────────────── │
  │                                │                               │
  │  GET /api/fortune              │                               │
  │  Authorization: Payment <cred> │                               │
  ├──────────────────────────────> │  PaymentIntent (SPT + confirm)│
  │                                ├─────────────────────────────> │
  │                                │              pi_... succeeded │
  │  200 + fortune + receipt       │<───────────────────────────── │
  │<────────────────────────────── │                               │
```

1. Client requests the fortune → server returns 402 with a payment challenge
2. mpp client calls `create_token` → POSTs to `/api/create-spt` → server creates SPT via Stripe
3. Client retries with a credential containing the SPT
4. Server creates a PaymentIntent with `shared_payment_granted_token` and `confirm=true`
5. On success, returns the fortune with a receipt
