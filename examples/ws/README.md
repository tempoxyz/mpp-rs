# WebSocket Payment Example

Demonstrates the MPP WebSocket payment flow with a server that streams
fortunes after payment verification.

## Running

```bash
# Start the server
cargo run --bin ws-server

# In another terminal, start the client
cargo run --bin ws-client
```

## Protocol

1. Client connects via WebSocket
2. Server sends `{ "type": "challenge", ... }`
3. Client responds with `{ "type": "credential", "credential": "Payment ..." }`
4. Server verifies payment and streams data as `{ "type": "message", "data": "..." }`
5. Server sends final `{ "type": "receipt", ... }` and closes

**Note:** This example uses a mock credential. In production, use
`TempoProvider` to sign real transactions.
