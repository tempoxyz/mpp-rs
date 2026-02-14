# Session Multi-Fetch Example

Demonstrates multiple paid requests over a single payment channel using the mpp Rust SDK.

This is the Rust port of the TypeScript `session/multi-fetch` example.

## How it works

1. **Server** exposes an `/api/scrape` endpoint that costs 0.01 pathUSD per request
2. **Client** opens a payment channel on the first request (on-chain)
3. Subsequent requests use off-chain vouchers — no gas, instant settlement
4. Each voucher is cumulative: request N carries a voucher for `N × 0.01` pathUSD
5. **Client** closes the channel, triggering on-chain settlement and refund of unused deposit

## Running

```bash
# Terminal 1: Start the server
cargo run --bin session-server

# Terminal 2: Run the client (needs a funded account)
PRIVATE_KEY=0x... cargo run --bin session-client
```

## Environment Variables

### Server
- None required (generates a random keypair on startup)

### Client
- `PRIVATE_KEY` — Hex-encoded private key (generates random if unset)
- `BASE_URL` — Server URL (default: `http://localhost:3000`)
