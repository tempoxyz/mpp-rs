# Axum Extractor

Demonstrates payment-gated endpoints using mpp's axum `MppCharge<C>` extractor.

The server exposes three endpoints:

- `GET /api/health` — Free, returns `{"status": "ok"}`
- `GET /api/fortune` — Costs $0.01 (`MppCharge<OneCent>`)
- `GET /api/premium` — Costs $1.00 (`MppCharge<OneDollar>`)

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

Define a `ChargeConfig` for each price point:

```rust
use mpp::server::axum::{ChargeConfig, MppCharge, WithReceipt};

struct OneCent;
impl ChargeConfig for OneCent {
    fn amount() -> &'static str { "0.01" }
}

struct OneDollar;
impl ChargeConfig for OneDollar {
    fn amount() -> &'static str { "1.00" }
    fn description() -> Option<&'static str> { Some("Premium content") }
}

async fn cheap(charge: MppCharge<OneCent>) -> WithReceipt<&'static str> {
    WithReceipt { receipt: charge.receipt, body: "cheap" }
}

async fn expensive(charge: MppCharge<OneDollar>) -> WithReceipt<&'static str> {
    WithReceipt { receipt: charge.receipt, body: "premium" }
}
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PRIVATE_KEY` | Random | Client's private key (hex, with or without `0x` prefix) |
| `BASE_URL` | `http://localhost:3000` | Client's base URL for the server |
| `RPC_URL` | `https://rpc.moderato.tempo.xyz` | Tempo RPC endpoint |
