# Session SSE Example

Pay-per-token LLM streaming using Server-Sent Events (SSE) with mpp session payments.

This mirrors the TypeScript `session/sse` example from the mpp SDK.

## How it works

1. **Client** sends a GET request to `/api/chat?prompt=...`
2. **Server** responds with 402 Payment Required + session challenge
3. **Client** opens a payment channel on-chain and sends an open credential
4. **Server** verifies the channel and responds 200
5. **Client** sends a GET with a voucher credential
6. **Server** begins streaming tokens as SSE events, charging per token
7. Mid-stream, if the channel balance is exhausted, the server emits
   `payment-need-voucher` events and the client sends updated vouchers

## Running

```bash
# Terminal 1: Start the server
cargo run --bin sse-server

# Terminal 2: Run the client
cargo run --bin sse-client -- "What is the meaning of life?"
```

## Architecture

- **Server** (`src/server.rs`): Axum server with session payment verification
  and metered SSE streaming via `mpp::server::sse::serve()`.
- **Client** (`src/client.rs`): reqwest client with `TempoSessionProvider` for
  automatic channel lifecycle management and SSE event parsing.
