# Axum Extractor

Demonstrates payment-gated endpoints using mpp's axum extractors (`MppCharge` and `MppChargeFor`).

The server exposes three endpoints:

- `GET /api/health` — Free, returns `{"status": "ok"}`
- `GET /api/fortune` — Costs $0.01 (default `MppCharge` extractor)
- `GET /api/premium` — Costs $1.00 (custom `MppChargeFor<OneDollar>` extractor)

The extractors handle the full 402 Payment Required flow automatically — no manual header parsing needed.

## Running

### 1. Start the server

```bash
cd examples/axum-extractor
cargo run --bin axum-server
```

The server listens on `http://localhost:3000`.

### 2. Run the client

In another terminal:

```bash
cd examples/axum-extractor
cargo run --bin axum-client
```

The client fetches both the cheap and premium fortune, handling 402 challenges automatically.

## Per-route pricing

The key pattern for per-route pricing:

```rust
use mpp::server::axum::{ChargeAmount, MppCharge, MppChargeFor, WithReceipt};

// Define a custom price
struct OneDollar;
impl ChargeAmount for OneDollar {
    fn amount() -> &'static str { "1.00" }
}

// Default $0.01
async fn cheap(charge: MppCharge) -> WithReceipt<&'static str> {
    WithReceipt { receipt: charge.receipt, body: "cheap" }
}

// Custom $1.00
async fn expensive(charge: MppChargeFor<OneDollar>) -> WithReceipt<&'static str> {
    WithReceipt { receipt: charge.receipt, body: "premium" }
}
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PRIVATE_KEY` | Random | Client's private key (hex, with or without `0x` prefix) |
| `BASE_URL` | `http://localhost:3000` | Client's base URL for the server |
| `RPC_URL` | `https://rpc.moderato.tempo.xyz` | Tempo RPC endpoint |
